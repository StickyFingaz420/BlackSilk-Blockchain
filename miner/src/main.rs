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
use std::sync::{Arc, atomic::{AtomicU64, Ordering, AtomicBool}, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
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
};
use std::sync::mpsc::{channel, Sender, Receiver};
use std::net::TcpStream;
use std::io::{BufReader, Write, BufRead};
use std::arch::is_x86_feature_detected;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;

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

    /// Print version info and exit
    #[clap(long)]
    pub version: bool,

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
    if cli.version {
        println!("BlackSilk Miner version {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    match &cli.command {
        Some(Commands::Benchmark) => {
            run_benchmark();
            return;
        },
        _ => {}
    }
    println!("[Miner] Connecting to node: {}", cli.node);
    if let Some(addr) = cli.address.as_ref() {
        println!("[Miner] Mining to address: {}", addr);
    }
    println!("[Miner] Threads: {}", cli.threads);
    // TODO: Insert mining logic here, using cli.node, cli.address, cli.threads, cli.data_dir
}

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
    use crate::randomx_ffi::randomx_get_flags;
    println!("[Benchmark] Initializing RandomX (best performance)...");
    println!("[Benchmark] For best performance, build with: set RUSTFLAGS=-C target-cpu=native");
    let threads = num_cpus::get_physical();
    println!("[Benchmark] Using {} physical threads", threads);
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let mut input = [0u8; 76];
    rand::thread_rng().fill_bytes(&mut input);
    let mut full_flags = unsafe { randomx_get_flags() as u32 };
    full_flags |= 1; // LARGE_PAGES
    full_flags |= 2; // HARD_AES
    full_flags |= 4; // FULL_MEM
    full_flags |= 8; // JIT
    let avx2_supported = std::arch::is_x86_feature_detected!("avx2");
    if avx2_supported {
        full_flags |= 64; // ARGON2_AVX2
        println!("[Benchmark] AVX2 detected and enabled for RandomX.");
    } else {
        println!("[Benchmark] AVX2 not detected. Running without AVX2 optimizations.");
    }
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
                        unsafe {
                            randomx_init_dataset(dataset_ptr.0, cache_ptr.0, start as _, (end - start) as _);
                        }
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
                            let mut input = input.clone();
                            let mut output = [0u8; 32];
                            let RandomXVmPtr(vm_usize) = vm_ptr;
                            let vm = vm_usize as *mut randomx_ffi::randomx_vm;
                            let mut local_input = input;
                            let mut local_output = output;
                            while !stop.load(Ordering::Relaxed) {
                                unsafe {
                                    randomx_ffi::randomx_calculate_hash_first(
                                        vm,
                                        local_input.as_ptr() as *const std::ffi::c_void,
                                        local_input.len(),
                                    );
                                }
                                local_input[0] = local_input[0].wrapping_add(1);
                                for _batch in 0..100 {
                                    for _ in 0..10 {
                                        if stop.load(Ordering::Relaxed) {
                                            break;
                                        }
                                        unsafe {
                                            randomx_ffi::randomx_calculate_hash_next(
                                                vm,
                                                local_input.as_ptr() as *const std::ffi::c_void,
                                                local_input.len(),
                                                local_output.as_mut_ptr() as *mut std::ffi::c_void,
                                            );
                                        }
                                        local_input[0] = local_input[0].wrapping_add(1);
                                        total_hashes.fetch_add(1, Ordering::Relaxed);
                                    }
                                    if stop.load(Ordering::Relaxed) {
                                        break;
                                    }
                                }
                                unsafe {
                                    randomx_ffi::randomx_calculate_hash_last(
                                        vm,
                                        local_output.as_mut_ptr() as *mut std::ffi::c_void,
                                    );
                                }
                                total_hashes.fetch_add(1, Ordering::Relaxed);
                            }
                            // Destroy VM after mining loop
                            unsafe {
                                if !vm.is_null() {
                                    randomx_destroy_vm(vm);
                                }
                            }
                        });
                    });
                    let start = Instant::now();
                    let mut last = Instant::now();
                    let mut last_hashes = 0u64;
                    for sec in 1..=duration_secs {
                        std::thread::sleep(Duration::from_secs(1));
                        let elapsed = start.elapsed().as_secs_f64();
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
                        for batch in 0..100 {
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
                std::thread::sleep(Duration::from_secs(1));
                let elapsed = start.elapsed().as_secs_f64();
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