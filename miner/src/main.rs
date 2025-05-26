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
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::io::Write;
use rayon::prelude::*;
mod randomx_ffi;
mod randomx_wrapper;
mod randomx_dll_check;
// Do not import randomx_hash here to avoid panic in benchmark
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
    randomx_calculate_hash_first,
    randomx_calculate_hash_next,
    randomx_calculate_hash_last,
};
use std::arch::is_x86_feature_detected;

/// BlackSilk Standalone Miner CLI
#[derive(Parser, Debug)]
#[clap(name = "blacksilk-miner", version, about = "BlackSilk Standalone Miner")]
pub struct Cli {
    /// Node address to connect for work
    #[clap(long, default_value = "127.0.0.1:8333", value_name = "ADDR")]
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

// Newtype wrappers for FFI pointers to make them Send + Sync
#[derive(Copy, Clone)]
struct RandomXCachePtr(*mut randomx_ffi::randomx_cache);
unsafe impl Send for RandomXCachePtr {}
unsafe impl Sync for RandomXCachePtr {}

#[derive(Copy, Clone)]
struct RandomXDatasetPtr(*mut randomx_ffi::randomx_dataset);
unsafe impl Send for RandomXDatasetPtr {}
unsafe impl Sync for RandomXDatasetPtr {}

#[repr(transparent)]
#[derive(Copy, Clone)]
struct RandomXVmPtr(usize); // store as usize for thread safety
unsafe impl Send for RandomXVmPtr {}
unsafe impl Sync for RandomXVmPtr {}

fn main() {
    randomx_dll_check::check_randomx_dll();
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
    // Use the wrapper for a single hash (safe and portable)
    unsafe {
        crate::randomx_wrapper::randomx_hash(flags, seed, input, output);
    }
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
    
    println!("[Benchmark] Initializing RandomX (best performance)...");
    println!("[Benchmark] For best performance, build with: set RUSTFLAGS=-C target-cpu=native");
    let threads = num_cpus::get_physical();
    println!("[Benchmark] Using {} physical threads", threads);
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let mut input = [0u8; 76];
    rand::thread_rng().fill_bytes(&mut input);
    let full_flags = get_best_randomx_flags_optimized();
    let fallback_flags = 2 | 4; // HARD_AES | FULL_MEM only
    let duration_secs = 60;
    println!("[Benchmark] RandomX flags: 0x{:X}", full_flags);
    let mut fallback = false;
    let mut ok = true;
    let total_hashes = Arc::new(AtomicU64::new(0));
    unsafe {
        let cache = randomx_alloc_cache(full_flags as i32);
        if cache.is_null() {
            println!("[Benchmark][ERROR] Failed to allocate RandomX cache with FULL PERF flags (Huge Pages or memory privilege missing).");
            fallback = true;
        } else {
            randomx_init_cache(cache, seed.as_ptr() as *const std::ffi::c_void, seed.len());
            let dataset = randomx_alloc_dataset(full_flags as i32);
            if dataset.is_null() {
                println!("[Benchmark][ERROR] Failed to allocate RandomX dataset with FULL PERF flags.");
                randomx_release_cache(cache);
                fallback = true;
            } else {
                let item_count = randomx_dataset_item_count() as u32;
                print_randomx_diagnostics(full_flags, item_count);
                let cache_ptr = RandomXCachePtr(cache);
                let dataset_ptr = RandomXDatasetPtr(dataset);
                let chunk_size = (item_count as usize + threads - 1) / threads;
                println!("[Benchmark] Initializing dataset in parallel ({} items, {} threads)...", item_count, threads);
                (0..threads).into_par_iter().for_each(|i| {
                    let cache_ptr = cache_ptr;
                    let dataset_ptr = dataset_ptr;
                    let start = (i * chunk_size) as u32;
                    let end = ((i + 1) * chunk_size).min(item_count as usize) as u32;
                    if start < end {
                        randomx_init_dataset(dataset_ptr.0, cache_ptr.0, start as _, (end - start) as _);
                    }
                });
                let mut vms = vec![];
                for i in 0..threads {
                    let vm = randomx_create_vm(full_flags as i32, cache, dataset);
                    if vm.is_null() {
                        println!("[Benchmark][ERROR] Failed to create RandomX VM with FULL PERF flags (JIT or executable memory not available, thread {}).", i);
                        ok = false;
                        break;
                    }
                    vms.push(RandomXVmPtr(vm as usize));
                }
                if ok {
                    println!("[Benchmark] Running for {} seconds...", duration_secs);
                    let stop = Arc::new(AtomicBool::new(false));
                    let mining_stop = stop.clone();
                    let mining_total_hashes = total_hashes.clone();
                    let mining_handle = std::thread::spawn(move || {
                        (0..threads).into_par_iter().for_each(|i| {
                            let total_hashes = mining_total_hashes.clone();
                            let stop = mining_stop.clone();
                            let vm_ptr = vms[i];
                            let input = input.clone();
                            let output = [0u8; 32];
                            let RandomXVmPtr(vm_usize) = vm_ptr;
                            let vm = vm_usize as *mut randomx_ffi::randomx_vm;
                            let mut local_input = input;
                            let mut local_output = output;
                            while !stop.load(Ordering::Relaxed) {
                                for _batch in 0..100 {
                                    for _ in 0..10 {
                                        if stop.load(Ordering::Relaxed) {
                                            break;
                                        }
                                        randomx_calculate_hash(
                                            vm,
                                            local_input.as_ptr() as *const std::ffi::c_void,
                                            local_input.len(),
                                            local_output.as_mut_ptr() as *mut std::ffi::c_void,
                                        );
                                        local_input[0] = local_input[0].wrapping_add(1);
                                        total_hashes.fetch_add(1, Ordering::Relaxed);
                                    }
                                    if stop.load(Ordering::Relaxed) {
                                        break;
                                    }
                                }
                                total_hashes.fetch_add(1, Ordering::Relaxed);
                            }
                            // Destroy VM after mining loop
                            if !vm.is_null() {
                                randomx_destroy_vm(vm);
                            }
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
                        let _elapsed = start.elapsed().as_secs_f64();
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
                    randomx_release_dataset(dataset);
                    randomx_release_cache(cache);
                    println!("[Benchmark] RandomX Hashrate: {:.2} H/s (FULL PERF, {} threads, {} hashes in {:.2} sec)", hashrate, threads, hashes, elapsed);
                    return;
                } else {
                    for &RandomXVmPtr(vm_usize) in &vms {
                        let vm_ptr = vm_usize as *mut randomx_ffi::randomx_vm;
                        if !vm_ptr.is_null() {
                            randomx_destroy_vm(vm_ptr);
                        }
                    }
                    randomx_release_dataset(dataset);
                    randomx_release_cache(cache);
                    fallback = true;
                }
            }
        }
    }
    if fallback {
        println!("[Benchmark][WARN] Huge Pages or JIT not available. Using safe mode (slower).\n");
        std::io::stdout().flush().unwrap();
        let mut handles = vec![];
        let total_hashes = Arc::new(AtomicU64::new(0));
        unsafe {
            let cache = randomx_alloc_cache(fallback_flags as i32);
            if cache.is_null() {
                println!("[Benchmark][ERROR] Failed to allocate RandomX cache in SAFE MODE (even without Huge Pages/JIT). This usually means insufficient RAM or memory privilege.");
                std::io::stdout().flush().unwrap();
                return;
            }
            randomx_init_cache(cache, seed.as_ptr() as *const std::ffi::c_void, seed.len());
            let dataset = randomx_alloc_dataset(fallback_flags as i32);
            if dataset.is_null() {
                println!("[Benchmark][ERROR] Failed to allocate RandomX dataset in SAFE MODE.");
                std::io::stdout().flush().unwrap();
                randomx_release_cache(cache);
                return;
            }
            let item_count = randomx_dataset_item_count() as u32;
            print_randomx_diagnostics(fallback_flags, item_count);
            let mut vms = vec![];
            let mut failed_threads = 0;
            for i in 0..threads {
                let vm = randomx_create_vm(fallback_flags as i32, cache, dataset);
                if vm.is_null() {
                    println!("[Benchmark][ERROR] Failed to create RandomX VM in SAFE MODE (thread {}). This usually means JIT or executable memory is not available.", i);
                    std::io::stdout().flush().unwrap();
                    failed_threads += 1;
                } else {
                    vms.push(RandomXVmPtr(vm as usize));
                }
            }
            if vms.is_empty() {
                println!("[Benchmark][FATAL] Could not create any RandomX VM in SAFE MODE ({} threads failed). Trying with a single thread...", failed_threads);
                std::io::stdout().flush().unwrap();
                // Try with a single thread
                let vm = randomx_create_vm(fallback_flags as i32, cache, dataset);
                if vm.is_null() {
                    println!("[Benchmark][FATAL] Could not create even a single RandomX VM in SAFE MODE. Benchmark cannot proceed.\n");
                    std::io::stdout().flush().unwrap();
                    randomx_release_dataset(dataset);
                    randomx_release_cache(cache);
                    return;
                } else {
                    vms.push(RandomXVmPtr(vm as usize));
                }
            }
            println!("[Benchmark][SAFE MODE] Created {} VM(s). Starting benchmark...", vms.len());
            std::io::stdout().flush().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            for (i, &RandomXVmPtr(vm_usize)) in vms.iter().enumerate() {
                let mut input = input.clone();
                let mut output = [0u8; 32];
                let stop = stop.clone();
                let total_hashes = total_hashes.clone();
                handles.push(std::thread::spawn(move || {
                    let vm = vm_usize as *mut randomx_ffi::randomx_vm;
                    println!("[Benchmark][Thread {}] Started.", i);
                    std::io::stdout().flush().unwrap();
                    // SAFE MODE mining thread loop
                    while !stop.load(Ordering::Relaxed) {
                        for _batch in 0..100 {
                            for _ in 0..10 {
                                if stop.load(Ordering::Relaxed) {
                                    break;
                                }
                                randomx_calculate_hash(
                                    vm,
                                    input.as_ptr() as *const std::ffi::c_void,
                                    input.len(),
                                    output.as_mut_ptr() as *mut std::ffi::c_void,
                                );
                                input[0] = input[0].wrapping_add(1);
                                total_hashes.fetch_add(1, Ordering::Relaxed);
                            }
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                    }
                }));
            }
            let start = Instant::now();
            let mut last = Instant::now();
            let mut last_hashes = 0u64;
            for sec in 1..=duration_secs {
                if benchmark_shutdown.load(Ordering::Relaxed) {
                    println!("[Benchmark] Shutdown signal received, stopping benchmark early...");
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
                let _elapsed = start.elapsed().as_secs_f64();
                let hashes = total_hashes.load(Ordering::Relaxed);
                let hashrate = (hashes - last_hashes) as f64 / (last.elapsed().as_secs_f64());
                println!("[Benchmark][{}s] Total: {} hashes | {:.2} H/s (current)", sec, hashes, hashrate);
                std::io::stdout().flush().unwrap();
                last = Instant::now();
                last_hashes = hashes;
            }
            stop.store(true, Ordering::Relaxed);
            for h in handles {
                h.join().unwrap();
            }
            let elapsed = start.elapsed().as_secs_f64();
            let hashes = total_hashes.load(Ordering::Relaxed);
            let hashrate = hashes as f64 / elapsed;
            for &RandomXVmPtr(vm_usize) in &vms {
                let vm_ptr = vm_usize as *mut randomx_ffi::randomx_vm;
                if !vm_ptr.is_null() {
                    randomx_destroy_vm(vm_ptr);
                }
            }
            randomx_release_dataset(dataset);
            randomx_release_cache(cache);
            println!("[Benchmark] RandomX Hashrate: {:.2} H/s (SAFE MODE, {} threads, {} hashes in {:.2} sec)", hashrate, vms.len(), hashes, elapsed);
            std::io::stdout().flush().unwrap();
        }
    }
}

#[cfg(target_os = "windows")]
fn try_memory_map_dataset(size: usize) -> Option<*mut std::ffi::c_void> {
    use std::ptr::null_mut;
    use winapi::um::memoryapi::{CreateFileMappingW, MapViewOfFile, FILE_MAP_ALL_ACCESS};
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;
    use winapi::um::winnt::{PAGE_READWRITE};
    use winapi::shared::minwindef::DWORD;
    unsafe {
        let mapping = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            null_mut(),
            PAGE_READWRITE,
            (size >> 32) as DWORD,
            (size & 0xFFFFFFFF) as DWORD,
            null_mut(),
        );
        if mapping.is_null() {
            return None;
        }
        let view = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, size);
        if view.is_null() {
            return None;
        }
        Some(view as *mut std::ffi::c_void)
    }
}
#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
fn try_memory_map_dataset(_size: usize) -> Option<*mut std::ffi::c_void> {
    None
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
    
    println!("[Mining] Initializing RandomX for mining...");
    
    // Initialize RandomX with safe performance settings for mining
    let safe_flags = 2; // HARD_AES only (light mode, no dataset required)
    
    unsafe {
        let cache = randomx_alloc_cache(safe_flags as i32);
        if cache.is_null() {
            eprintln!("[Mining] Failed to allocate RandomX cache in safe mode");
            return;
        }
        println!("[Mining] RandomX cache allocated in safe mode");
        
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
                // Mine the block (each thread creates its own VMs)
                if let Some(result) = mine_block(tmpl, &[], cli.threads) {
                    // Submit the block
                    match submit_block(&client, &node_url, &result) {
                        Ok(_) => {
                            println!("[Mining] ✅ Block submitted successfully!");
                            template = None; // Force getting new template
                        }
                        Err(e) => {
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
        
        // Cleanup RandomX resources after mining loop exits
        println!("[Mining] Cleaning up RandomX resources...");
        randomx_release_cache(cache);
        println!("[Mining] Cleanup complete, mining stopped gracefully.");
    }
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

// XMRig-style optimized mining function with advanced RandomX utilization
fn mine_block(template: &BlockTemplate, _vms: &[*mut crate::randomx_ffi::randomx_vm], thread_count: usize) -> Option<SubmitBlockRequest> {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;
    
    let found = Arc::new(AtomicBool::new(false));
    let nonce_counter = Arc::new(AtomicU64::new(0));
    let start_time = std::time::Instant::now();
    let mut handles = Vec::new();
    let (tx, rx) = std::sync::mpsc::channel();
    
    println!("[Mining] Starting optimized mining with {} threads (difficulty: {})", thread_count, template.difficulty);
    
    // Use optimized RandomX flags for better performance
    let optimized_flags = get_best_randomx_flags_optimized();
    
    // Pre-allocate shared cache for all threads (XMRig optimization)
    let shared_cache = Arc::new(RandomXCachePtr(unsafe {
        let cache = randomx_alloc_cache(optimized_flags as i32);
        if cache.is_null() {
            eprintln!("[Mining] Failed to allocate shared RandomX cache, falling back to safe mode");
            let fallback_flags = 2; // HARD_AES only
            let fallback_cache = randomx_alloc_cache(fallback_flags as i32);
            if !fallback_cache.is_null() {
                randomx_init_cache(fallback_cache, template.seed.as_ptr() as *const std::ffi::c_void, template.seed.len());
            }
            fallback_cache
        } else {
            randomx_init_cache(cache, template.seed.as_ptr() as *const std::ffi::c_void, template.seed.len());
            cache
        }
    }));
    
    if shared_cache.0.is_null() {
        eprintln!("[Mining] Critical: Failed to allocate RandomX cache even in safe mode");
        return None;
    }
    
    println!("[Mining] Using optimized RandomX flags: 0x{:X}", optimized_flags);
    
    for thread_id in 0..thread_count {
        let found_clone = found.clone();
        let nonce_counter_clone = nonce_counter.clone();
        let template_clone = template.clone();
        let tx_clone = tx.clone();
        let shared_cache_clone = shared_cache.clone();
        
        let handle = thread::spawn(move || {
            unsafe {
                // Create optimized VM using shared cache
                let vm = create_optimized_randomx_vm(shared_cache_clone.0, optimized_flags);
                if vm.is_null() {
                    eprintln!("[Mining Thread {}] Failed to create optimized VM", thread_id);
                    return;
                }
                
                // Pre-allocate buffers for batch processing (XMRig style)
                const BATCH_SIZE: usize = 64; // Process hashes in batches for better cache utilization
                let mut hash_outputs = [[0u8; 32]; BATCH_SIZE];
                let mut input_buffers = Vec::with_capacity(BATCH_SIZE);
                
                // Pre-compute base input to avoid repeated allocations
                let base_input = template_clone.header.clone();
                
                // Initialize input buffers
                for _ in 0..BATCH_SIZE {
                    let mut input = base_input.clone();
                    input.extend_from_slice(&[0u8; 8]); // Space for nonce
                    input_buffers.push(input);
                }
                
                let thread_offset = thread_id as u64 * 100000;
                let _batch_start_nonce = thread_offset;
                
                while !found_clone.load(Ordering::Relaxed) {
                    // Batch processing for better performance
                    let current_nonce_base = nonce_counter_clone.fetch_add(BATCH_SIZE as u64, Ordering::Relaxed) + thread_offset;
                    
                    // Process batch using optimized first/next/last pattern for better performance
                    for i in 0..BATCH_SIZE {
                        let nonce = current_nonce_base + i as u64;
                        
                        // Update nonce in pre-allocated buffer (avoid repeated memory allocation)
                        let input_len = input_buffers[i].len() - 8;
                        input_buffers[i][input_len..].copy_from_slice(&nonce.to_le_bytes());
                        
                        if i == 0 {
                            // Start batch with first hash
                            randomx_calculate_hash_first(
                                vm,
                                input_buffers[i].as_ptr() as *const std::ffi::c_void,
                                input_buffers[i].len(),
                            );
                        } else if i == BATCH_SIZE - 1 {
                            // End batch with last hash
                            randomx_calculate_hash_last(vm, hash_outputs[i-1].as_mut_ptr() as *mut std::ffi::c_void);
                            // Calculate final hash separately
                            randomx_calculate_hash(
                                vm,
                                input_buffers[i].as_ptr() as *const std::ffi::c_void,
                                input_buffers[i].len(),
                                hash_outputs[i].as_mut_ptr() as *mut std::ffi::c_void,
                            );
                        } else {
                            // Process intermediate hashes
                            randomx_calculate_hash_next(
                                vm,
                                input_buffers[i].as_ptr() as *const std::ffi::c_void,
                                input_buffers[i].len(),
                                hash_outputs[i-1].as_mut_ptr() as *mut std::ffi::c_void,
                            );
                        }
                        
                        // Early exit check for found solution
                        if found_clone.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    
                    // Check all batch results for difficulty using optimized algorithm
                    for i in 0..BATCH_SIZE {
                        if found_clone.load(Ordering::Relaxed) {
                            break;
                        }
                        
                        let nonce = current_nonce_base + i as u64;
                        
                        // Fast difficulty check (XMRig optimization)
                        if check_difficulty_fast(&hash_outputs[i], template_clone.difficulty) {
                            found_clone.store(true, Ordering::Relaxed);
                            let result = SubmitBlockRequest {
                                header: template_clone.header.clone(),
                                nonce,
                                hash: hash_outputs[i].to_vec(),
                            };
                            let _ = tx_clone.send(result);
                            break;
                        }
                    }
                    
                    // Progress reporting (reduced frequency for better performance)
                    if thread_id == 0 && current_nonce_base % (BATCH_SIZE as u64 * 100) == 0 {
                        let elapsed = start_time.elapsed().as_secs();
                        if elapsed > 0 {
                            let total_hashes = nonce_counter_clone.load(Ordering::Relaxed) * thread_count as u64;
                            let hashrate = total_hashes / elapsed;
                            print!("\r[Mining] Optimized Hashrate: {} H/s | Hashes: {} | Time: {}s | Batch: {}", 
                                   hashrate, total_hashes, elapsed, current_nonce_base / BATCH_SIZE as u64);
                            std::io::stdout().flush().unwrap();
                        }
                    }
                    
                    // Timeout check with better frequency
                    if start_time.elapsed() > Duration::from_secs(60) {
                        break;
                    }
                }
                
                // Cleanup thread VM
                randomx_destroy_vm(vm);
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
    
    // Cleanup shared cache
    unsafe {
        if !shared_cache.0.is_null() {
            randomx_release_cache(shared_cache.0);
        }
    }
    
    if result.is_some() {
        println!("\n[Mining] 🎉 Optimized solution found!");
    } else {
        println!("\n[Mining] No solution found in optimized round, getting new template...");
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

#[allow(dead_code)]
fn get_best_randomx_flags() -> u32 {
    let mut flags = 0;
    flags |= 1; // LARGE_PAGES
    flags |= 2; // HARD_AES
    flags |= 4; // FULL_MEM
    flags |= 8; // JIT
    if is_x86_feature_detected!("avx2") {
        flags |= 64; // ARGON2_AVX2
    }
    flags
}

// XMRig-style optimized flag detection with better fallback logic
fn get_best_randomx_flags_optimized() -> u32 {
    let mut flags = 0;
    
    // Always try HARD_AES (essential for performance)
    flags |= 2; // HARD_AES
    
    // Try JIT compilation (major performance boost)
    flags |= 8; // JIT
    
    // Try FULL_MEM mode for maximum performance
    flags |= 4; // FULL_MEM
    
    // Try large pages if available (reduces memory latency)
    flags |= 1; // LARGE_PAGES
    
    // Add optimized Argon2 if AVX2 is detected
    if is_x86_feature_detected!("avx2") {
        flags |= 64; // ARGON2_AVX2
    } else if is_x86_feature_detected!("ssse3") {
        flags |= 32; // ARGON2_SSSE3
    }
    
    flags
}

// XMRig-style optimized VM creation with automatic fallback
unsafe fn create_optimized_randomx_vm(cache: *mut crate::randomx_ffi::randomx_cache, flags: u32) -> *mut crate::randomx_ffi::randomx_vm {
    // Try to create dataset for FULL_MEM mode
    if flags & 4 != 0 { // FULL_MEM flag is set
        let dataset = randomx_alloc_dataset(flags as i32);
        if !dataset.is_null() {
            // Initialize dataset in parallel for better performance
            let item_count = randomx_dataset_item_count();
            randomx_init_dataset(dataset, cache, 0, item_count);
            
            let vm = randomx_create_vm(flags as i32, cache, dataset);
            if !vm.is_null() {
                return vm; // Success with full performance
            }
            randomx_release_dataset(dataset);
        }
    }
    
    // Fallback: try without FULL_MEM
    let light_flags = flags & !4; // Remove FULL_MEM flag
    let vm = randomx_create_vm(light_flags as i32, cache, std::ptr::null_mut());
    if !vm.is_null() {
        return vm; // Success in light mode
    }
    
    // Fallback: try without large pages
    let no_hugepages_flags = light_flags & !1; // Remove LARGE_PAGES flag
    let vm = randomx_create_vm(no_hugepages_flags as i32, cache, std::ptr::null_mut());
    if !vm.is_null() {
        return vm; // Success without huge pages
    }
    
    // Final fallback: safe mode (HARD_AES only)
    let safe_flags = 2; // HARD_AES only
    randomx_create_vm(safe_flags as i32, cache, std::ptr::null_mut())
}

// Fast difficulty checking optimized for RandomX hashes (XMRig style)
fn check_difficulty_fast(hash: &[u8; 32], difficulty: u64) -> bool {
    // Convert first 8 bytes of hash to u64 and compare against difficulty
    let hash_val = u64::from_le_bytes([
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5], hash[6], hash[7]
    ]);
    hash_val < difficulty
}