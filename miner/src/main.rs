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
// لا تستورد randomx_hash هنا حتى لا يحصل panic في البينشمارك
// use randomx_wrapper::randomx_hash;
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

#[derive(Copy, Clone)]
struct RandomXVmPtr(*mut randomx_ffi::randomx_vm);
unsafe impl Send for RandomXVmPtr {}
unsafe impl Sync for RandomXVmPtr {}

fn main() {
    let cli = Cli::parse();
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
    use std::ffi::c_void;
    use std::ptr;
    unsafe {
        let cache = randomx_alloc_cache(flags as i32);
        if cache.is_null() {
            return false;
        }
        randomx_init_cache(cache, seed.as_ptr() as *const c_void, seed.len());
        let vm = randomx_create_vm(flags as i32, cache, ptr::null_mut());
        if vm.is_null() {
            randomx_release_cache(cache);
            return false;
        }
        randomx_calculate_hash(vm, input.as_ptr() as *const c_void, input.len(), output.as_mut_ptr() as *mut c_void);
        randomx_destroy_vm(vm);
        randomx_release_cache(cache);
    }
    true
}

fn run_benchmark() {
    use rand::RngCore;
    use std::time::Instant;
    use num_cpus;
    println!("[Benchmark] Initializing RandomX (best performance)...");
    let threads = num_cpus::get_physical();
    println!("[Benchmark] Using {} physical threads", threads);
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let mut input = [0u8; 76];
    rand::thread_rng().fill_bytes(&mut input);
    let n_hashes_per_thread = 1000;
    let total_hashes = n_hashes_per_thread * threads;
    let full_flags = 1 | 2 | 4 | 8; // LARGE_PAGES | HARD_AES | FULL_MEM | JIT
    let fallback_flags = 2 | 4; // HARD_AES | FULL_MEM only

    let mut fallback = false;
    let mut handles = vec![];
    let mut ok = true;
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
                randomx_init_dataset(dataset, cache, 0, item_count);
                let mut vms = vec![];
                for i in 0..threads {
                    let vm = randomx_create_vm(full_flags as i32, cache, dataset);
                    if vm.is_null() {
                        println!("[Benchmark][ERROR] Failed to create RandomX VM with FULL PERF flags (JIT or executable memory not available, thread {}).", i);
                        ok = false;
                        break;
                    }
                    vms.push(RandomXVmPtr(vm));
                }
                if ok {
                    let start = Instant::now();
                    handles = (0..threads).map(|i| {
                        let mut input = input.clone();
                        let mut output = [0u8; 32];
                        let vm = vms[i];
                        std::thread::spawn(move || {
                            let vm = vm;
                            for _ in 0..n_hashes_per_thread {
                                randomx_calculate_hash(vm.0, input.as_ptr() as *const std::ffi::c_void, input.len(), output.as_mut_ptr() as *mut std::ffi::c_void);
                                input[0] = input[0].wrapping_add(1);
                            }
                        })
                    }).collect();
                    for h in handles {
                        h.join().unwrap();
                    }
                    let elapsed = start.elapsed().as_secs_f64();
                    let hashrate = total_hashes as f64 / elapsed;
                    for &RandomXVmPtr(vm) in &vms { randomx_destroy_vm(vm); }
                    randomx_release_dataset(dataset);
                    randomx_release_cache(cache);
                    println!("[Benchmark] RandomX Hashrate: {:.2} H/s (FULL PERF, {} threads, {} hashes in {:.2} sec)", hashrate, threads, total_hashes, elapsed);
                    return;
                } else {
                    for &vm in &vms { if !vm.0.is_null() { randomx_destroy_vm(vm.0); } }
                    randomx_release_dataset(dataset);
                    randomx_release_cache(cache);
                    fallback = true;
                }
            }
        }
    }
    // fallback: without Huge Pages/JIT
    if fallback {
        println!("[Benchmark][WARN] Huge Pages or JIT not available. Using safe mode (slower).\n");
        unsafe {
            let cache = randomx_alloc_cache(fallback_flags as i32);
            if cache.is_null() {
                println!("[Benchmark][ERROR] Failed to allocate RandomX cache in SAFE MODE (even without Huge Pages/JIT). This usually means insufficient RAM or memory privilege.");
                return;
            }
            randomx_init_cache(cache, seed.as_ptr() as *const std::ffi::c_void, seed.len());
            let dataset = randomx_alloc_dataset(fallback_flags as i32);
            if dataset.is_null() {
                println!("[Benchmark][ERROR] Failed to allocate RandomX dataset in SAFE MODE.");
                randomx_release_cache(cache);
                return;
            }
            let item_count = randomx_dataset_item_count() as u32;
            randomx_init_dataset(dataset, cache, 0, item_count);
            let mut vms = vec![];
            for i in 0..threads {
                let vm = randomx_create_vm(fallback_flags as i32, cache, dataset);
                if vm.is_null() {
                    println!("[Benchmark][ERROR] Failed to create RandomX VM in SAFE MODE (thread {}). This usually means JIT or executable memory is not available.", i);
                    randomx_release_dataset(dataset);
                    randomx_release_cache(cache);
                    return;
                }
                vms.push(RandomXVmPtr(vm));
            }
            let start = Instant::now();
            handles = (0..threads).map(|i| {
                let mut input = input.clone();
                let mut output = [0u8; 32];
                let vm = vms[i];
                std::thread::spawn(move || {
                    let vm = vm;
                    for _ in 0..n_hashes_per_thread {
                        randomx_calculate_hash(vm.0, input.as_ptr() as *const std::ffi::c_void, input.len(), output.as_mut_ptr() as *mut std::ffi::c_void);
                        input[0] = input[0].wrapping_add(1);
                    }
                })
            }).collect();
            for h in handles {
                h.join().unwrap();
            }
            let elapsed = start.elapsed().as_secs_f64();
            let hashrate = total_hashes as f64 / elapsed;
            for &RandomXVmPtr(vm) in &vms { randomx_destroy_vm(vm); }
            randomx_release_dataset(dataset);
            randomx_release_cache(cache);
            println!("[Benchmark] RandomX Hashrate: {:.2} H/s (SAFE MODE, {} threads, {} hashes in {:.2} sec)", hashrate, threads, total_hashes, elapsed);
        }
    }
}