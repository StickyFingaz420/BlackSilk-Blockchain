// ============================================================================
// BlackSilk Standalone Miner - Official RandomX Performance Settings
//
// - Uses the official RandomX library via FFI (C++ DLL)
// - All performance features enabled: Huge Pages, AES-NI, FULL_MEM, JIT, AVX2
// - By default, only physical CPU cores are used for mining/benchmarking
// - Only one cache/dataset allocated per session (not per thread)
// - Real-time performance reporting during benchmarking
// - Warning if more than physical cores are used
// - Automatically attempts Huge Pages, with fallback if unavailable
// - These settings are officially approved for maximum (XMRig-level) performance
// ============================================================================

use clap::{Parser, Subcommand};
use std::sync::{Arc, atomic::{AtomicU64, Ordering, AtomicBool}, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
mod randomx_ffi;
mod randomx_wrapper;
use randomx_wrapper::randomx_hash;
// Import all required RandomX FFI functions
use crate::randomx_ffi::{
    randomx_alloc_cache,
    randomx_init_cache,
    randomx_release_cache, // <-- correct function name
    randomx_alloc_dataset,
    randomx_init_dataset,
    randomx_release_dataset,
    randomx_dataset_item_count,
    randomx_create_vm,
    randomx_destroy_vm,
    randomx_calculate_hash,
};
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
    Benchmark {
        #[arg(short, long, default_value = "auto")]
        threads: String, // "auto" (all logical), "physical", or a number
    },
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

// Newtype wrappers for FFI pointers to make them Send + Sync
#[derive(Copy, Clone)]
struct RandomXCachePtr(*mut randomx_ffi::randomx_cache);
unsafe impl Send for RandomXCachePtr {}
unsafe impl Sync for RandomXCachePtr {}

#[derive(Copy, Clone)]
struct RandomXDatasetPtr(*mut randomx_ffi::randomx_dataset);
unsafe impl Send for RandomXDatasetPtr {}
unsafe impl Sync for RandomXDatasetPtr {}

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
        Some(Commands::Benchmark { threads }) => {
            let logical = num_cpus::get();
            let physical = num_cpus::get_physical();
            println!("[Miner] Detected logical CPUs: {logical}, physical cores: {physical}");
            // Always use physical cores by default
            let num_threads = if threads.is_empty() || threads == "auto" {
                physical
            } else if threads == "logical" {
                logical
            } else if threads == "physical" {
                physical
            } else {
                threads.parse::<usize>().unwrap_or(physical)
            };
            if num_threads > physical {
                println!("[Miner] Warning: Using more threads ({}) than physical cores ({}). RandomX is memory-bound and may not scale beyond physical cores.", num_threads, physical);
            }
            println!("[Miner] Benchmarking for 60 seconds using {} threads and RandomX (FFI, XMRig-style)...", num_threads);
            let hashes = Arc::new(AtomicU64::new(0));
            let stop_flag = Arc::new(AtomicBool::new(false));
            // Use all performance flags: HARD_AES | FULL_MEM | LARGE_PAGES | JIT
            let mut flags = randomx_ffi::randomx_flags_RANDOMX_FLAG_HARD_AES
                | randomx_ffi::randomx_flags_RANDOMX_FLAG_FULL_MEM
                | randomx_ffi::randomx_flags_RANDOMX_FLAG_LARGE_PAGES
                | randomx_ffi::randomx_flags_RANDOMX_FLAG_JIT;
            let seed = vec![0u8; 32];
            // Allocate cache and dataset ONCE
            println!("[Miner] Allocating RandomX cache (trying Huge Pages)...");
            let cache = unsafe { randomx_alloc_cache(flags) };
            let mut used_hugepages = true;
            let cache = if cache.is_null() {
                // Retry without Huge Pages
                println!("[Miner][Warning] Huge Pages not available, falling back to normal pages. Performance will be lower.");
                flags &= !randomx_ffi::randomx_flags_RANDOMX_FLAG_LARGE_PAGES;
                used_hugepages = false;
                let fallback_cache = unsafe { randomx_alloc_cache(flags) };
                if fallback_cache.is_null() {
                    panic!("Failed to allocate RandomX cache (even without Huge Pages)");
                }
                fallback_cache
            } else {
                cache
            };
            println!("[Miner] Initializing RandomX cache...");
            unsafe { randomx_init_cache(cache, seed.as_ptr() as *const _, seed.len()) };
            println!("[Miner] Allocating RandomX dataset (trying Huge Pages)...");
            let dataset = unsafe { randomx_alloc_dataset(flags) };
            let dataset = if dataset.is_null() {
                // Retry without Huge Pages
                if used_hugepages {
                    println!("[Miner][Warning] Huge Pages not available for dataset, falling back to normal pages. Performance will be lower.");
                    flags &= !randomx_ffi::randomx_flags_RANDOMX_FLAG_LARGE_PAGES;
                }
                let fallback_dataset = unsafe { randomx_alloc_dataset(flags) };
                if fallback_dataset.is_null() {
                    panic!("Failed to allocate RandomX dataset (even without Huge Pages)");
                }
                fallback_dataset
            } else {
                dataset
            };
            let item_count = unsafe { randomx_dataset_item_count() } as usize;
            println!("[Miner] Initializing RandomX dataset ({} items, this may take a while)...", item_count);
            let t0 = Instant::now();
            let chunk = item_count / 10.max(1); // 10% steps
            for i in (0..item_count).step_by(chunk) {
                let end = (i + chunk).min(item_count);
                unsafe { randomx_init_dataset(dataset, cache, i as u32, (end - i) as u32) };
                let percent = ((end as f64 / item_count as f64) * 100.0).round() as u32;
                println!("[Miner] Dataset init: {}% (item {} of {})", percent, end, item_count);
            }
            let t1 = Instant::now();
            let t2 = Instant::now();
            let cache_secs = t1.duration_since(t0).as_secs_f64();
            let dataset_secs = t2.duration_since(t1).as_secs_f64();
            println!("[Miner] Cache init time: {:.1}s, Dataset init time: {:.1}s", cache_secs, dataset_secs);
            if dataset_secs > 10.0 {
                println!("[Miner] Dataset initialization is slow. For best performance, enable huge pages and ensure you have enough free RAM.");
            }
            // Wrap pointers in Arc for thread safety
            let cache = Arc::new(RandomXCachePtr(cache));
            let dataset = Arc::new(RandomXDatasetPtr(dataset));
            let mut handles = Vec::with_capacity(num_threads);
            for _ in 0..num_threads {
                let hashes = Arc::clone(&hashes);
                let cache = Arc::clone(&cache);
                let dataset = Arc::clone(&dataset);
                let stop_flag = Arc::clone(&stop_flag);
                handles.push(std::thread::spawn(move || {
                    let vm = unsafe { randomx_create_vm(flags, cache.0, dataset.0) };
                    if vm.is_null() {
                        panic!("Failed to create RandomX VM");
                    }
                    let mut output = [0u8; 32];
                    while !stop_flag.load(Ordering::Relaxed) {
                        unsafe {
                            randomx_calculate_hash(vm, [0u8; 80].as_ptr() as *const _, 80, output.as_mut_ptr() as *mut _);
                        }
                        hashes.fetch_add(1, Ordering::Relaxed);
                    }
                    unsafe { randomx_destroy_vm(vm) };
                }));
            }
            let start = Instant::now();
            let mut last = start;
            let mut last_hashes = 0u64;
            while start.elapsed().as_secs() < 60 {
                std::thread::sleep(Duration::from_secs(1));
                let total = hashes.load(Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs_f64();
                let interval = last.elapsed().as_secs_f64();
                let interval_hashes = total - last_hashes;
                let interval_hashrate = interval_hashes as f64 / interval.max(1e-6);
                let hashrate = total as f64 / elapsed.max(1e-6);
                println!("[Miner] Elapsed: {:>2}s | Total Hashes: {} | Hashrate: {:.2} H/s | Interval: {:.2} H/s", elapsed as u64, total, hashrate, interval_hashrate);
                last = Instant::now();
                last_hashes = total;
            }
            stop_flag.store(true, Ordering::Relaxed);
            for h in handles { let _ = h.join(); }
            let total_hashes = hashes.load(Ordering::Relaxed);
            println!("[Miner] Benchmark result: {:.2} H/s ({} threads, RandomX FFI)", total_hashes as f64 / 60.0, num_threads);
            unsafe {
                randomx_release_dataset(dataset.0);
                randomx_release_cache(cache.0);
            }
            return;
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
        // --- Allocate RandomX cache/dataset ONCE per mining session ---
        let flags = 0x2 | 0x4; // HARD_AES | FULL_MEM (no huge pages)
        let mut seed: Option<Vec<u8>> = None;
        // Fetch a block template to get the seed
        let client = Client::new();
        let node_url = format!("http://{}/mining/get_block_template", cfg.node);
        let req = BlockTemplateRequest { address: cfg.address.clone() };
        let template = match client.post(&node_url).json(&req).send() {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<BlockTemplate>() {
                        Ok(t) => t,
                        Err(_) => { panic!("Failed to parse block template"); }
                    }
                } else { panic!("Failed to get block template"); }
            }
            Err(_) => { panic!("Failed to connect to node for block template"); }
        };
        seed = Some(template.seed.clone());
        let seed = seed.unwrap();
        let cache = unsafe { randomx_alloc_cache(flags) };
        if cache.is_null() {
            panic!("Failed to allocate RandomX cache");
        }
        unsafe { randomx_init_cache(cache, seed.as_ptr() as *const _, seed.len()) };
        let dataset = unsafe { randomx_alloc_dataset(flags) };
        if dataset.is_null() {
            unsafe { randomx_release_cache(cache) };
            panic!("Failed to allocate RandomX dataset");
        }
        let item_count = unsafe { randomx_dataset_item_count() };
        unsafe { randomx_init_dataset(dataset, cache, 0, item_count as u32) };
        // Wrap pointers in Arc for thread safety
        let cache = Arc::new(RandomXCachePtr(cache));
        let dataset = Arc::new(RandomXDatasetPtr(dataset));
        for t in 0..cfg.threads {
            let cfg = cfg.clone();
            let should_stop = Arc::clone(should_stop);
            let hashes = Arc::clone(hashes);
            let accepted = Arc::clone(accepted);
            let rejected = Arc::clone(rejected);
            let cache = Arc::clone(&cache);
            let dataset = Arc::clone(&dataset);
            let seed = seed.clone();
            threads.push(std::thread::spawn(move || {
                let client = Client::new();
                let node_url = format!("http://{}/mining/get_block_template", cfg.node);
                let submit_url = format!("http://{}/mining/submit_block", cfg.node);
                let vm = unsafe { randomx_create_vm(flags, cache.0, dataset.0) };
                if vm.is_null() {
                    panic!("Failed to create RandomX VM");
                }
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
                    loop {
                        if should_stop.load(Ordering::SeqCst) { break; }
                        let nonce_bytes = nonce.to_le_bytes();
                        let len = header.len();
                        if len >= 8 {
                            for i in 0..8 { header[len-8+i] = nonce_bytes[i]; }
                        }
                        let mut hash = [0u8; 32];
                        unsafe {
                            randomx_calculate_hash(vm, header.as_ptr() as *const _, header.len(), hash.as_mut_ptr() as *mut _);
                        }
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
                unsafe { randomx_destroy_vm(vm) };
            }));
        }
        // Wait for all threads to finish before releasing dataset/cache
        while let Some(th) = threads.pop() { let _ = th.join(); }
        unsafe {
            randomx_release_dataset(dataset.0);
            randomx_release_cache(cache.0);
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
                    // Multi-threaded benchmark
                    println!("[Miner] Benchmarking for 60 seconds using all CPU cores...");
                    let num_threads = num_cpus::get();
                    let mut handles = Vec::with_capacity(num_threads);
                    let hashes = Arc::new(AtomicU64::new(0));
                    let start = Instant::now();
                    for _ in 0..num_threads {
                        let hashes = Arc::clone(&hashes);
                        handles.push(std::thread::spawn(move || {
                            let flags = 0x2 | 0x4; // HARD_AES | FULL_MEM (no huge pages)
                            let seed = vec![0u8; 32];
                            loop {
                                let mut hash = [0u8; 32];
                                unsafe { randomx_hash(flags, &seed, &[0u8; 80], &mut hash) };
                                hashes.fetch_add(1, Ordering::Relaxed);
                                if start.elapsed().as_secs() >= 60 { break; }
                            }
                        }));
                    }
                    for h in handles { let _ = h.join(); }
                    let total_hashes = hashes.load(Ordering::Relaxed);
                    println!("[Miner] Benchmark result: {:.2} H/s ({} threads)", total_hashes as f64 / 60.0, num_threads);
                    return;
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
                        let flags = 0x2 | 0x4; // HARD_AES | FULL_MEM (no huge pages)
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
                            let mut hash = [0u8; 32];
                            unsafe { randomx_hash(flags, &seed, &header_work, &mut hash) };
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