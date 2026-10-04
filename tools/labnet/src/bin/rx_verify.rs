//! `blacksilk-rx-verify`: re-checks the proof of work of a node's chain in a
//! fresh process, after a lab run.
//!
//! Evidence tooling (docs/evidence/rx-fullmode-seedswitch-2026-09-29), not
//! used by any node, miner or wallet. It changes nothing on the nodes; it only
//! reads their `/headers`.
//!
//! 1. **Agreement:** the headers of every given node, byte for byte, up to the
//!    lowest of their tips.
//! 2. **Light mode:** every header's RandomX hash, from fresh light caches
//!    built here. The key height comes from this file's own copy of the key
//!    schedule (Monero's: epoch 2048, lag 64), the key from the header
//!    chain fetched, and the target check is this file's own 256-bit multiply
//!    against the header's difficulty.
//! 3. **Consensus:** the same headers are fed to a `HeaderChain` (difficulty,
//!    timestamps, linkage, PoW) whose PoW function answers from step 2 and
//!    fails the run if consensus asks for a key other than the one step 2
//!    derived.
//! 4. **Full mode:** for the heights in `--full`, the hash again with a full
//!    2 GiB dataset per key, compared bit for bit with the light-mode hash.
//!
//! It uses the same `blacksilk-randomx` crate as the node: this is not a
//! second implementation. The crate's conformance to the reference is shown
//! by its vectors (randomx/tests); what this adds is a check of the real
//! blocks of a run, outside the processes that produced and accepted them,
//! and the full/light agreement on those blocks.

#![forbid(unsafe_code)]

#[path = "../build_guard.rs"]
mod build_guard;

use blacksilk_consensus::{
    BlockHeader, ChainParams, Hash, HeaderChain, Network, PowFunction, HEADER_SIZE,
};
use blacksilk_randomx::{Cache, Dataset, Vm};
use blacksilk_rpc::{Client, MAX_HEADERS_PER_REQUEST};
use clap::Parser;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "blacksilk-rx-verify",
    about = "Re-check the RandomX proof of work of a lab run's chain in a fresh process"
)]
struct Args {
    /// Node RPC address; repeat for every node to compare.
    #[arg(long, required = true)]
    node: Vec<String>,
    /// The RPC cookie of each `--node`, in the same order.
    #[arg(long, required = true)]
    cookie: Vec<PathBuf>,
    #[arg(long, default_value = "regtest")]
    network: String,
    /// Heights re-hashed in full mode, e.g. `2100-2130,2300-2313`.
    #[arg(long, default_value = "")]
    full: String,
    /// Threads for the light hashes and for each dataset build.
    #[arg(long, default_value_t = 4)]
    threads: usize,
    /// Heights whose records are written out in full (as `--full`); every
    /// `--full` height is included.
    #[arg(long, default_value = "")]
    record: String,
    /// JSON report.
    #[arg(long)]
    out: PathBuf,
    /// Check only heights 1 ..= this one.
    #[arg(long)]
    up_to: Option<u64>,
    /// Negative control: after the agreement check, change the nonce of
    /// the header at this height, which must be the last one checked
    /// (`--up-to`). The run must then FAIL.
    #[arg(long, requires = "up_to")]
    corrupt_nonce: Option<u64>,
}

/// The key schedule (Monero's: epoch 2048, lag 64), written out here rather
/// than taken from `blacksilk_consensus::seed_height`: the key height of a
/// block at `height`.
fn key_height(height: u64, epoch: u64, lag: u64) -> u64 {
    if height <= epoch + lag {
        0
    } else {
        (height - lag - 1) / epoch * epoch
    }
}

/// `hash` (256-bit little-endian) times `difficulty` is below 2^256,
/// computed with 32-bit limbs (a different route from the node's 64-bit one).
fn meets_target(hash: &Hash, difficulty: u64) -> bool {
    if difficulty == 0 {
        return false;
    }
    let d = [difficulty & 0xffff_ffff, difficulty >> 32];
    // product = hash * d, in 32-bit limbs; the top limbs must be zero.
    let mut limbs = [0u64; 10];
    for (i, c) in hash.as_chunks::<4>().0.iter().enumerate() {
        let h = u32::from_le_bytes(*c) as u64;
        for (j, dj) in d.iter().enumerate() {
            let mut k = i + j;
            let mut carry = h * dj;
            while carry != 0 {
                let sum = limbs[k] + (carry & 0xffff_ffff);
                limbs[k] = sum & 0xffff_ffff;
                carry = (carry >> 32) + (sum >> 32);
                k += 1;
            }
        }
    }
    limbs[8] == 0 && limbs[9] == 0
}

fn parse_heights(s: &str) -> BTreeSet<u64> {
    let mut out = BTreeSet::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b): (u64, u64) = (a.parse().expect("height"), b.parse().expect("height"));
                out.extend(a..=b);
            }
            None => {
                out.insert(part.parse().expect("height"));
            }
        }
    }
    out
}

fn fetch_headers(client: &Client) -> Vec<[u8; HEADER_SIZE]> {
    let mut out = Vec::new();
    let mut from = 1;
    loop {
        let page = client
            .headers(from, MAX_HEADERS_PER_REQUEST)
            .expect("/headers");
        let bytes = hex::decode(&page.headers).expect("header hex");
        if bytes.is_empty() {
            break;
        }
        let (whole, rest) = bytes.as_chunks::<HEADER_SIZE>();
        assert!(rest.is_empty(), "a partial header in /headers");
        out.extend_from_slice(whole);
        from = 1 + out.len() as u64;
        if from > page.height {
            break;
        }
    }
    out
}

/// PoW answers for the header chain, from the hashes computed beforehand.
/// A key other than the one derived independently fails the run.
struct Precomputed {
    hashes: BTreeMap<[u8; HEADER_SIZE], (Hash, Hash)>,
    mismatched_keys: Mutex<Vec<u64>>,
}

impl PowFunction for Precomputed {
    fn pow_hash(&self, seed: &Hash, header_bytes: &[u8]) -> Hash {
        let key: [u8; HEADER_SIZE] = header_bytes.try_into().expect("header size");
        match self.hashes.get(&key) {
            Some((s, h)) if s == seed => *h,
            _ => {
                let height = BlockHeader::from_bytes(header_bytes).map_or(u64::MAX, |h| h.height);
                self.mismatched_keys.lock().unwrap().push(height);
                // A hash that meets no target: the header is refused.
                [0xff; 32]
            }
        }
    }
}

#[derive(Serialize)]
struct Record {
    height: u64,
    id: String,
    timestamp: u64,
    difficulty: u64,
    key_height: u64,
    key: String,
    light_hash: String,
    meets_target: bool,
    full_hash: Option<String>,
    full_matches_light: Option<bool>,
}

#[derive(Serialize, Default)]
struct KeyStats {
    key_height: u64,
    key: String,
    first_height: u64,
    last_height: u64,
    headers: u64,
    cache_build_secs: f64,
    light_hash_secs: f64,
    dataset_build_secs: Option<f64>,
    full_compared: u64,
}

#[derive(Serialize, Default)]
struct Report {
    started_unix: u64,
    /// This binary's `build flags:` line (always `none`: a build with
    /// test-only code refuses to run, W4-GUARD).
    build_flags: String,
    network: String,
    nodes: Vec<String>,
    node_heights: Vec<u64>,
    /// Headers compared across all nodes (1 ..= this height).
    common_height: u64,
    nodes_agree: bool,
    /// Heights where some node's header differs from the first node's.
    disagreements: Vec<u64>,
    light_checked: u64,
    light_failures: Vec<u64>,
    consensus_accepted: u64,
    consensus_error: Option<String>,
    consensus_key_mismatches: Vec<u64>,
    consensus_tip_matches: bool,
    full_compared: u64,
    full_mismatches: Vec<u64>,
    keys: Vec<KeyStats>,
    threads: usize,
    /// `--corrupt-nonce`: the height whose nonce was changed (a run that
    /// must fail).
    negative_control: Option<u64>,
    all_passed: bool,
    records: Vec<Record>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn main() {
    let a: Args = build_guard::parse_args();
    let build_flags = build_guard::require_clean_build("blacksilk-rx-verify");
    assert_eq!(a.node.len(), a.cookie.len(), "one --cookie per --node");
    let net = match a.network.as_str() {
        "regtest" => Network::Regtest,
        "testnet" => Network::Testnet,
        other => panic!("unsupported network {other}"),
    };
    let params = ChainParams::for_network(net);
    let nid = params.network_id;
    let (epoch, lag) = (params.seed_epoch, params.seed_lag);
    let threads = a.threads.max(1);
    let full_set = parse_heights(&a.full);
    let mut record_set = parse_heights(&a.record);
    record_set.extend(full_set.iter().copied());
    let mut r = Report {
        started_unix: unix_now(),
        build_flags,
        network: a.network.clone(),
        nodes: a.node.clone(),
        threads,
        negative_control: a.corrupt_nonce,
        ..Default::default()
    };

    // 1. Agreement.
    let chains: Vec<Vec<[u8; HEADER_SIZE]>> = a
        .node
        .iter()
        .zip(&a.cookie)
        .map(|(n, c)| {
            let client = Client::try_new(n)
                .and_then(|x| x.with_cookie_file(c))
                .expect("client");
            let hs = fetch_headers(&client);
            eprintln!("{n}: {} headers", hs.len());
            hs
        })
        .collect();
    r.node_heights = chains.iter().map(|c| c.len() as u64).collect();
    let common = chains.iter().map(Vec::len).min().unwrap_or(0);
    r.common_height = common as u64;
    for i in 0..common {
        if chains.iter().any(|c| c[i] != chains[0][i]) {
            r.disagreements.push(i as u64 + 1);
        }
    }
    r.nodes_agree = r.disagreements.is_empty() && common > 0;
    let common = common.min(a.up_to.map_or(usize::MAX, |h| h as usize));
    r.common_height = r.common_height.min(common as u64);
    let mut headers: Vec<BlockHeader> = chains[0][..common]
        .iter()
        .map(|b| BlockHeader::from_bytes(b).expect("header"))
        .collect();
    if let Some(h) = a.corrupt_nonce {
        assert_eq!(
            h as usize, common,
            "--corrupt-nonce must be the --up-to height"
        );
        let last = headers.last_mut().expect("at least one header");
        last.nonce ^= 1;
        eprintln!("negative control: nonce of header {h} changed");
    }
    let mut ids: Vec<Hash> = vec![params.genesis.id(nid)];
    for (i, h) in headers.iter().enumerate() {
        assert_eq!(h.height, i as u64 + 1, "heights are consecutive");
        assert_eq!(h.prev_id, ids[i], "header {} does not link", h.height);
        ids.push(h.id(nid));
    }

    // 2. Light mode, per key.
    let mut by_key: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, h) in headers.iter().enumerate() {
        by_key
            .entry(key_height(h.height, epoch, lag))
            .or_default()
            .push(i);
    }
    let mut light: Vec<Hash> = vec![[0; 32]; headers.len()];
    for (&kh, idx) in &by_key {
        let key = ids[kh as usize];
        let t = Instant::now();
        let cache = Cache::new(&key);
        let cache_secs = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let chunk = idx.len().div_ceil(threads);
        let results: Vec<Vec<(usize, Hash)>> = std::thread::scope(|s| {
            idx.chunks(chunk.max(1))
                .map(|part| {
                    let cache = &cache;
                    let headers = &headers;
                    s.spawn(move || {
                        let mut vm = Vm::light(cache);
                        part.iter()
                            .map(|&i| (i, vm.hash(&headers[i].to_bytes())))
                            .collect()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().expect("light hashing thread"))
                .collect()
        });
        for (i, h) in results.into_iter().flatten() {
            light[i] = h;
        }
        let secs = t.elapsed().as_secs_f64();
        eprintln!(
            "key height {kh}: {} light hashes in {secs:.1} s (cache {cache_secs:.1} s)",
            idx.len()
        );
        r.keys.push(KeyStats {
            key_height: kh,
            key: hex::encode(key),
            first_height: headers[idx[0]].height,
            last_height: headers[*idx.last().expect("non-empty")].height,
            headers: idx.len() as u64,
            cache_build_secs: cache_secs,
            light_hash_secs: secs,
            ..Default::default()
        });
    }
    for (i, h) in headers.iter().enumerate() {
        r.light_checked += 1;
        if !meets_target(&light[i], h.difficulty) {
            r.light_failures.push(h.height);
        }
    }

    // 3. Consensus header validation on the precomputed hashes.
    let pre = Arc::new(Precomputed {
        hashes: headers
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let key = ids[key_height(h.height, epoch, lag) as usize];
                (h.to_bytes(), (key, light[i]))
            })
            .collect(),
        mismatched_keys: Mutex::new(Vec::new()),
    });
    let mut chain = HeaderChain::new(params.clone(), pre.clone());
    let now = unix_now();
    for h in &headers {
        match chain.accept(*h, now) {
            Ok(_) => r.consensus_accepted += 1,
            Err(e) => {
                r.consensus_error = Some(format!("height {}: {e}", h.height));
                break;
            }
        }
    }
    r.consensus_key_mismatches = pre.mismatched_keys.lock().unwrap().clone();
    r.consensus_tip_matches = chain.tip_id() == *ids.last().expect("genesis at least");

    // 4. Full mode for the chosen heights, one dataset at a time.
    let mut full: BTreeMap<u64, Hash> = BTreeMap::new();
    for ks in &mut r.keys {
        let want: Vec<usize> = by_key[&ks.key_height]
            .iter()
            .copied()
            .filter(|&i| full_set.contains(&headers[i].height))
            .collect();
        if want.is_empty() {
            continue;
        }
        let key = ids[ks.key_height as usize];
        let t = Instant::now();
        let dataset = Dataset::new(&Cache::new(&key), threads);
        ks.dataset_build_secs = Some(t.elapsed().as_secs_f64());
        eprintln!(
            "key height {}: dataset built in {:.1} s",
            ks.key_height,
            t.elapsed().as_secs_f64()
        );
        let mut vm = Vm::full(&dataset);
        for i in want {
            full.insert(headers[i].height, vm.hash(&headers[i].to_bytes()));
            ks.full_compared += 1;
        }
    }
    for (&height, fh) in &full {
        r.full_compared += 1;
        if *fh != light[height as usize - 1] {
            r.full_mismatches.push(height);
        }
    }

    for (i, h) in headers.iter().enumerate() {
        if !record_set.contains(&h.height) {
            continue;
        }
        let kh = key_height(h.height, epoch, lag);
        let fh = full.get(&h.height);
        r.records.push(Record {
            height: h.height,
            id: hex::encode(ids[i + 1]),
            timestamp: h.timestamp,
            difficulty: h.difficulty,
            key_height: kh,
            key: hex::encode(ids[kh as usize]),
            light_hash: hex::encode(light[i]),
            meets_target: meets_target(&light[i], h.difficulty),
            full_hash: fh.map(hex::encode),
            full_matches_light: fh.map(|f| *f == light[i]),
        });
    }
    r.all_passed = r.nodes_agree
        && r.light_failures.is_empty()
        && r.consensus_error.is_none()
        && r.consensus_key_mismatches.is_empty()
        && r.consensus_accepted == headers.len() as u64
        && r.consensus_tip_matches
        && r.full_mismatches.is_empty()
        && r.full_compared == full_set.iter().filter(|&&h| h as usize <= common).count() as u64;
    let json = serde_json::to_string_pretty(&r).expect("json");
    std::fs::write(&a.out, &json).expect("write report");
    eprintln!(
        "nodes agree {} (1..={}), light {} checked / {} failed, consensus accepted {}, full {} compared / {} mismatched: {}",
        r.nodes_agree,
        r.common_height,
        r.light_checked,
        r.light_failures.len(),
        r.consensus_accepted,
        r.full_compared,
        r.full_mismatches.len(),
        if r.all_passed { "PASS" } else { "FAIL" }
    );
    std::process::exit(if r.all_passed { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_schedule_matches_rx0() {
        assert_eq!(key_height(2112, 2048, 64), 0);
        assert_eq!(key_height(2113, 2048, 64), 2048);
        assert_eq!(key_height(4160, 2048, 64), 2048);
        assert_eq!(key_height(4161, 2048, 64), 4096);
        for h in 0..10_000 {
            assert_eq!(
                key_height(h, 2048, 64),
                blacksilk_consensus::seed_height(h, 2048, 64)
            );
        }
    }

    #[test]
    fn target_check_agrees_with_the_node() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let mut h = [0u8; 32];
            for c in h.as_chunks_mut::<8>().0 {
                *c = next().to_le_bytes();
            }
            // Clear 0 to 32 of the most significant bytes, so that both
            // outcomes occur.
            let zero = (next() % 33) as usize;
            for b in &mut h[32 - zero..] {
                *b = 0;
            }
            let d = match next() % 4 {
                0 => next(),
                1 => next() % 1000,
                2 => u64::MAX,
                _ => 1u64 << (next() % 64),
            };
            assert_eq!(
                meets_target(&h, d),
                blacksilk_consensus::check_hash(&h, d),
                "hash {} difficulty {d}",
                hex::encode(h)
            );
        }
        assert!(meets_target(&[0xff; 32], 1));
        assert!(!meets_target(&[0xff; 32], 2));
        assert!(!meets_target(&[0; 32], 0));
    }
}
