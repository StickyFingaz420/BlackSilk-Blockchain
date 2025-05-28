// ============================================================================
// BlackSilk Standalone Miner - Pure Rust RandomX Implementation
//
// - Uses pure Rust RandomX implementation (no external C libraries)
// - Cross-platform compatible without FFI dependencies
// - No build dependencies on external RandomX libraries
// - Self-contained and portable across all platforms
// - Professional-grade performance without external binaries
// ============================================================================

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::io::Write;
use rayon::prelude::*;

// Pure Rust RandomX modules (no FFI required)
mod randomx;

// Use new comprehensive RandomX implementation
use crate::randomx::*;

// Global hash counter for hashrate reporting
static HASH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// BlackSilk Standalone Miner CLI
#[derive(Parser, Debug)]
#[clap(name = "blacksilk-miner", version, about = "BlackSilk Standalone Miner")]
pub struct Cli {
    /// Node address to connect for work
    #[clap(long, default_value = "127.0.0.1:9333", value_name = "ADDR")]
    pub node: String,

    /// Mining address (where rewards go)
    #[clap(long, value_name = "ADDR")]
    pub address: Option<String>,

    /// Number of mining threads
    #[clap(long, default_value = "1")]
    pub threads: usize,

    /// Data directory for miner state
    #[clap(long, default_value = "./miner_data", value_name = "DIR")]
    pub data_dir: PathBuf,

    #[clap(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run RandomX benchmark and print hashrate
    Benchmark,
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
    miner_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockTemplateRequest {
    address: String,
}

#[derive(Debug)]
#[allow(dead_code)]
struct Args {
    node: String,
    address: String,
    threads: usize,
    stratum: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct MinerConfig {
    node: String,
    address: String,
    threads: usize,
}

#[allow(dead_code)]
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
    // No DLL check needed for pure Rust implementation
    let mut cli = Cli::parse();
    
    // Automatically use all physical CPU threads if --threads is not set by user
    if cli.threads == 1 {
        let physical = num_cpus::get_physical();
        cli.threads = physical;
        println!("[Miner] Auto-detected physical threads: {}", physical);
    }
    
    match &cli.command {
        Some(Commands::Benchmark) => {
            run_benchmark();
            return;
        },
        _ => {}
    }
    
    // Start mining
    if let Some(addr) = cli.address.as_ref() {
        println!("[Miner] Connecting to node: {}", cli.node);
        println!("[Miner] Mining to address: {}", addr);
        println!("[Miner] Threads: {}", cli.threads);
        start_mining(&cli);
    } else {
        println!("[Miner] Error: Mining address required. Use --address <ADDR>");
        println!("[Miner] Example: --address BlackSilk1234567890abcdef");
    }
}

#[allow(dead_code)]
fn try_randomx_hash(flags: u32, seed: &[u8], input: &[u8], output: &mut [u8]) -> bool {
    // Use the new comprehensive Rust Native RandomX implementation
    let hash = randomx_hash(seed, input);
    output[..32].copy_from_slice(&hash);
    true
}

fn print_randomx_diagnostics(flags: u32, item_count: u32) {
    let huge_pages = (flags & 1) != 0;
    let hard_aes = (flags & 2) != 0;
    let full_mem = (flags & 4) != 0;
    let jit = (flags & 8) != 0;
    let avx2 = (flags & 64) != 0;
    let dataset_bytes = item_count as u64 * 64;
    println!("[RandomX Diagnostics] Flags: 0x{:X}", flags);
    println!("[RandomX Diagnostics] Huge Pages: {}", if huge_pages { "ENABLED" } else { "DISABLED" });
    println!("[RandomX Diagnostics] JIT: {}", if jit { "ENABLED" } else { "DISABLED" });
    println!("[RandomX Diagnostics] FULL_MEM: {}", if full_mem { "ENABLED" } else { "DISABLED" });
    println!("[RandomX Diagnostics] HARD_AES: {}", if hard_aes { "ENABLED" } else { "DISABLED" });
    println!("[RandomX Diagnostics] AVX2: {}", if avx2 { "ENABLED" } else { "DISABLED" });
    println!("[RandomX Diagnostics] Dataset size: {:.2} MB ({} items)", dataset_bytes as f64 / (1024.0 * 1024.0), item_count);
}

fn run_benchmark() {
    use rand::RngCore;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use num_cpus;
    
    // Set up signal handler for graceful shutdown during benchmark
    let benchmark_shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = benchmark_shutdown.clone();
    
    ctrlc::set_handler(move || {
        println!("\n[Benchmark] Received shutdown signal, stopping benchmark...");
        shutdown_clone.store(true, Ordering::Relaxed);
    }).expect("Error setting Ctrl-C handler");
    
    println!("[Benchmark] Initializing Pure Rust RandomX (best performance)...");
    println!("[Benchmark] For best performance, build with: set RUSTFLAGS=-C target-cpu=native");
    let threads = num_cpus::get_physical();
    println!("[Benchmark] Using {} physical threads", threads);
    
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let mut input = [0u8; 76];
    rand::thread_rng().fill_bytes(&mut input);
    
    let flags = get_optimal_flags();
    let duration_secs = 60;
    
    println!("[Benchmark] RandomX flags: 0x{:X}", flags);
    print_randomx_diagnostics(flags, (DATASET_SIZE / 64) as u32);
    
    println!("[Benchmark] Initializing RandomX cache with Argon2d...");
    let cache = RandomXCache::new(&seed);
    
    println!("[Benchmark] Initializing full 2.08 GB dataset...");
    let dataset = RandomXDataset::new(&cache, threads);
    
    println!("[Benchmark] Creating VMs for {} threads...", threads);
    let total_hashes = Arc::new(AtomicU64::new(0));
    
    println!("[Benchmark] Running for {} seconds...", duration_secs);
    let stop = Arc::new(AtomicBool::new(false));
    let mining_stop = stop.clone();
    let mining_total_hashes = total_hashes.clone();
    
    let mining_handle = std::thread::spawn(move || {
        (0..threads).into_par_iter().for_each(|thread_id| {
            let total_hashes = mining_total_hashes.clone();
            let stop = mining_stop.clone();
            let mut vm = RandomXVM::new(&cache, Some(&dataset));
            let mut local_input = input;
            local_input[0] = thread_id as u8; // Give each thread unique input
            
            println!("[Thread {}] Starting mining loop", thread_id);
            let mut hash_count = 0u64;
            
            while !stop.load(Ordering::Relaxed) {
                if hash_count % 10 == 0 {
                    println!("[Thread {}] Computing hash #{}", thread_id, hash_count);
                }
                
                let _output = vm.calculate_hash(&local_input);
                local_input[0] = local_input[0].wrapping_add(1);
                total_hashes.fetch_add(1, Ordering::Relaxed);
                hash_count += 1;
                
                // Add small delay to avoid overwhelming output
                if hash_count % 10 == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
            
            println!("[Thread {}] Mining loop ended with {} hashes", thread_id, hash_count);
        });
    });
    
    let start = Instant::now();
    let mut last = Instant::now();
    let mut last_hashes = 0u64;
    
    for sec in 1..=duration_secs {
        if benchmark_shutdown.load(Ordering::Relaxed) {
            println!("[Benchmark] Shutdown signal received, stopping benchmark early...");
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
        let hashes = total_hashes.load(Ordering::Relaxed);
        let hashrate = (hashes - last_hashes) as f64 / (last.elapsed().as_secs_f64());
        println!("[Benchmark][{}s] Total: {} hashes | {:.2} H/s (current)", sec, hashes, hashrate);
        last = Instant::now();
        last_hashes = hashes;
    }
    
    stop.store(true, Ordering::Relaxed);
    mining_handle.join().unwrap();
    
    let elapsed = start.elapsed().as_secs_f64();
    let hashes = total_hashes.load(Ordering::Relaxed);
    let hashrate = hashes as f64 / elapsed;
    
    println!("[Benchmark] Pure Rust RandomX Hashrate: {:.2} H/s ({} threads, {} hashes in {:.2} sec)", 
             hashrate, threads, hashes, elapsed);
}

fn start_mining(cli: &Cli) {
    // Set up signal handler for graceful shutdown
    let shutdown_signal = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown_signal.clone();
    
    // Handle Ctrl+C (SIGINT) for graceful shutdown
    ctrlc::set_handler(move || {
        println!("\n[Mining] Received shutdown signal, preparing for graceful exit...");
        shutdown_clone.store(true, Ordering::Relaxed);
    }).expect("Error setting Ctrl-C handler");
    
    let client = Client::new();
    let node_url = if cli.node.starts_with("http://") || cli.node.starts_with("https://") {
        cli.node.clone()
    } else {
        format!("http://{}", cli.node)
    };
    let address = cli.address.as_ref().unwrap();
    
    println!("[Mining] Initializing Pure Rust RandomX for mining...");
    
    // Initialize RandomX with optimal performance settings
    let flags = get_optimal_flags();
    println!("[Mining] Using RandomX flags: 0x{:X}", flags);
    
    // Global hashrate tracking
    let mining_start_time = std::time::Instant::now();
    let last_report_time = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
    let last_hash_count = Arc::new(AtomicU64::new(0));
    
    // Spawn hashrate reporting thread
    let hashrate_shutdown = shutdown_signal.clone();
    let hashrate_last_report = last_report_time.clone();
    let hashrate_last_count = last_hash_count.clone();
    
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(10));
            
            if hashrate_shutdown.load(Ordering::Relaxed) {
                break;
            }
            
            let current_hashes = HASH_COUNTER.load(Ordering::Relaxed);
            let current_time = std::time::Instant::now();
            
            let mut last_time = hashrate_last_report.lock().unwrap();
            let last_count = hashrate_last_count.load(Ordering::Relaxed);
            
            let time_diff = current_time.duration_since(*last_time).as_secs_f64();
            let hash_diff = current_hashes.saturating_sub(last_count);
            
            if time_diff > 0.0 {
                let current_hashrate = hash_diff as f64 / time_diff;
                let total_time = current_time.duration_since(mining_start_time).as_secs();
                let avg_hashrate = if total_time > 0 { current_hashes as f64 / total_time as f64 } else { 0.0 };
                
                println!("[Hashrate] Current: {:.2} H/s | Average: {:.2} H/s | Total hashes: {} | Uptime: {}s", 
                        current_hashrate, avg_hashrate, current_hashes, total_time);
            }
            
            *last_time = current_time;
            hashrate_last_count.store(current_hashes, Ordering::Relaxed);
        }
    });
    
    // Start mining loop
    let mut current_seed = Vec::new();
    let mut template: Option<BlockTemplate> = None;
    let mut template_time = std::time::Instant::now();
    
    loop {
        // Check for shutdown signal
        if shutdown_signal.load(Ordering::Relaxed) {
            println!("[Mining] Shutdown signal received, breaking from mining loop...");
            break;
        }
        
        // Get new block template every 30 seconds or if we don't have one
        if template.is_none() || template_time.elapsed() > Duration::from_secs(30) {
            match get_block_template(&client, &node_url, address) {
                Ok(new_template) => {
                    let seed_changed = current_seed != new_template.seed;
                    
                    if seed_changed {
                        println!("[Mining] New seed detected for next mining round");
                        current_seed = new_template.seed.clone();
                    }
                    
                    template = Some(new_template);
                    template_time = std::time::Instant::now();
                    println!("[Mining] New block template received");
                }
                Err(e) => {
                    eprintln!("[Mining] Failed to get block template: {}", e);
                    thread::sleep(Duration::from_secs(5));
                    continue;
                }
            }
        }
        
        if let Some(ref tmpl) = template {
            // Mine the block using pure Rust implementation
            if let Some(result) = mine_block_pure_rust(tmpl, cli.threads, address) {
                // BLOCK FOUND! Add special celebration message
                println!("\n🎉🎉🎉 BLOCK FOUND! 🎉🎉🎉");
                println!("🔥 Nonce: {}", result.nonce);
                println!("💎 Hash: {}", hex::encode(&result.hash));
                println!("⚡ Submitting to node...\n");
                
                // Submit the block
                match submit_block(&client, &node_url, &result) {
                    Ok(_) => {
                        println!("🚀🚀🚀 VICTORY! BLOCK ACCEPTED BY NODE! 🚀🚀🚀");
                        println!("✅ Block submitted successfully and verified by RandomX!");
                        println!("🏆 You just mined a new block on the BlackSilk blockchain!");
                        println!("💰 Block reward will be sent to: {}\n", address);
                        template = None; // Force getting new template
                    }
                    Err(e) => {
                        println!("❌ Block submission failed: {}", e);
                        eprintln!("[Mining] Failed to submit block: {}", e);
                    }
                }
            } else {
                // No solution found in this round, get new template
                template = None;
            }
        }
        
        thread::sleep(Duration::from_millis(100));
    }
    
    println!("[Mining] Mining stopped gracefully.");
}

fn get_block_template(client: &Client, node_url: &str, address: &str) -> Result<BlockTemplate, Box<dyn std::error::Error>> {
    let request = BlockTemplateRequest {
        address: address.to_string(),
    };
    
    let response = client
        .post(&format!("{}/mining/get_block_template", node_url))
        .json(&request)
        .send()?;
    
    if !response.status().is_success() {
        return Err(format!("Node returned error: {}", response.status()).into());
    }
    
    // Parse the response which has additional fields
    #[derive(Deserialize)]
    struct NodeBlockTemplate {
        header: Vec<u8>,
        difficulty: u64,
        seed: Vec<u8>,
        coinbase_address: String,
        #[allow(dead_code)]
        height: u64,
        #[allow(dead_code)]
        prev_hash: Vec<u8>,
        #[allow(dead_code)]
        timestamp: u64,
    }
    
    let node_template: NodeBlockTemplate = response.json()?;
    
    // Convert to our format
    let template = BlockTemplate {
        header: node_template.header,
        difficulty: node_template.difficulty,
        seed: node_template.seed,
        coinbase_address: node_template.coinbase_address,
    };
    
    Ok(template)
}

// Pure Rust mining function - no FFI dependencies
fn mine_block_pure_rust(template: &BlockTemplate, thread_count: usize, miner_address: &str) -> Option<SubmitBlockRequest> {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;
    
    let found = Arc::new(AtomicBool::new(false));
    let nonce_counter = Arc::new(AtomicU64::new(0));
    let start_time = std::time::Instant::now();
    let mut handles = Vec::new();
    let (tx, rx) = std::sync::mpsc::channel();
    
    println!("[Mining] Starting Rust Native RandomX mining with {} threads (difficulty: {})", thread_count, template.difficulty);
    
    let flags = get_optimal_flags();
    
    // Initialize shared RandomX components with full 2.08 GB dataset
    println!("[Mining] Creating RandomX cache with Argon2d (seed length: {})", template.seed.len());
    let cache = Arc::new(RandomXCache::new(&template.seed));
    
    println!("[Mining] Expanding to 2.08 GB dataset using SuperscalarHash...");
    let dataset = if (flags & RANDOMX_FLAG_FULL_MEM) != 0 {
        Some(Arc::new(RandomXDataset::new(&cache, thread_count)))
    } else {
        None
    };
    
    println!("[Mining] RandomX initialization complete, creating {} mining threads...", thread_count);
    
    for thread_id in 0..thread_count {
        let found_clone = found.clone();
        let nonce_counter_clone = nonce_counter.clone();
        let template_clone = template.clone();
        let tx_clone = tx.clone();
        let cache_clone = cache.clone();
        let dataset_clone = dataset.clone();
        let miner_address_clone = miner_address.to_string();
        
        let handle = thread::spawn(move || {
            println!("[Mining] Thread {} creating RandomX VM...", thread_id);
            let mut vm = RandomXVM::new(&cache_clone, dataset_clone.as_ref().map(|d| d.as_ref()));
            let thread_offset = thread_id as u64 * 100000;
            println!("[Mining] Thread {} started with offset {} (Rust Native RandomX VM ready)", thread_id, thread_offset);
            
            while !found_clone.load(Ordering::Relaxed) {
                let nonce = nonce_counter_clone.fetch_add(1, Ordering::Relaxed) + thread_offset;
                
                if nonce % 100 == 0 {
                    println!("[Mining] Thread {} computing hash #{} (nonce={})", thread_id, nonce - thread_offset, nonce);
                }
                
                // Prepare input with nonce
                let mut input = template_clone.header.clone();
                input.extend_from_slice(&nonce.to_le_bytes());
                
                // Calculate hash using Rust Native RandomX implementation
                let start_hash = std::time::Instant::now();
                let hash_output = vm.calculate_hash(&input);
                let hash_time = start_hash.elapsed();
                
                if nonce % 100 == 0 {
                    println!("[Mining] Thread {} completed hash #{} in {:?} (output: {}...)", 
                             thread_id, nonce - thread_offset, hash_time, 
                             hex::encode(&hash_output[..8]));
                }
                
                // Increment global hash counter for hashrate reporting
                HASH_COUNTER.fetch_add(1, Ordering::Relaxed);
                
                // Check difficulty
                if check_difficulty_fast(&hash_output, template_clone.difficulty) {
                    found_clone.store(true, Ordering::Relaxed);
                    let result = SubmitBlockRequest {
                        header: template_clone.header.clone(),
                        nonce,
                        hash: hash_output.to_vec(),
                        miner_address: Some(miner_address_clone.clone()),
                    };
                    let _ = tx_clone.send(result);
                    break;
                }
                
                // Progress reporting
                if thread_id == 0 && nonce % 10000 == 0 {
                    let elapsed = start_time.elapsed().as_secs();
                    if elapsed > 0 {
                        let total_hashes = nonce_counter_clone.load(Ordering::Relaxed) * thread_count as u64;
                        let hashrate = total_hashes / elapsed;
                        print!("\r[Mining] Rust Native RandomX: {} H/s | Hashes: {} | Time: {}s", 
                               hashrate, total_hashes, elapsed);
                        std::io::stdout().flush().unwrap();
                    }
                }
                
                // Timeout check
                if start_time.elapsed() > Duration::from_secs(60) {
                    break;
                }
            }
        });
        
        handles.push(handle);
    }
    
    // Wait for result or timeout
    let result = rx.recv_timeout(Duration::from_secs(60)).ok();
    
    // Signal all threads to stop
    found.store(true, Ordering::Relaxed);
    
    // Wait for all threads to finish
    for handle in handles {
        let _ = handle.join();
    }
    
    if result.is_some() {
        println!("\n[Mining] 🎉 Rust Native RandomX solution found!");
    } else {
        println!("\n[Mining] No solution found in Rust Native RandomX round, getting new template...");
    }
    
    result
}

fn submit_block(client: &Client, node_url: &str, block: &SubmitBlockRequest) -> Result<(), Box<dyn std::error::Error>> {
    let response = client
        .post(&format!("{}/mining/submit_block", node_url))
        .json(block)
        .send()?;
    
    if !response.status().is_success() {
        let error_text = response.text()?;
        return Err(format!("Failed to submit block: {}", error_text).into());
    }
    
    Ok(())
}

// Rust Native RandomX flag detection with CPU-only optimization
fn get_optimal_flags() -> u32 {
    use crate::randomx::{RANDOMX_FLAG_DEFAULT, RANDOMX_FLAG_HARD_AES, RANDOMX_FLAG_FULL_MEM};
    
    // For pure Rust implementation, we use default flags
    // Hardware AES and full memory mode flags
    RANDOMX_FLAG_DEFAULT | RANDOMX_FLAG_HARD_AES | RANDOMX_FLAG_FULL_MEM
}

// Fast difficulty checking optimized for RandomX hashes
fn check_difficulty_fast(hash: &[u8; 32], difficulty: u64) -> bool {
    // Convert first 8 bytes of hash to u64 and compare against difficulty
    let hash_val = u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7]
    ]);
    hash_val < difficulty
}
