//! `blacksilk-labnet`: long-duration network test on one machine.
//!
//! - Starts N real `blacksilk-node` processes (regtest by default).
//! - Connects them in a ring with chords, every link going through a proxy that
//!   adds latency and jitter.
//! - Runs `blacksilk-miner` on two nodes, one in each partition group.
//! - Drives in-process wallets that send transactions through random nodes.
//! - Periodically partitions the network into two groups, both of which keep
//!   mining, then heals it, forcing reorganizations.
//!
//! Throughout it records heights, tips, mempools, peers and memory, and checks
//! invariants. At the end it verifies:
//! - convergence;
//! - a late-joining node discovering peers and syncing;
//! - every wallet restored from its seed against the fresh node seeing the same
//!   balance;
//! - supply conservation (Σ wallet balances = coins generated).
//!
//! This is not a substitute for multi-machine testing (docs/testnet.md §7). It
//! exercises the same code paths under controlled latency and partitions.

#![forbid(unsafe_code)]

mod proxy;

use blacksilk_chain::emission::{format_amount, COIN};
use blacksilk_consensus::{ChainParams, Network};
use blacksilk_rpc::{Client, Info};
use blacksilk_tx::params::TxRules;
use blacksilk_wallet::Wallet;
use clap::Parser;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Parser, Clone)]
#[command(about = "BlackSilk lab network: long-duration multi-node test")]
struct Args {
    /// Directory with blacksilk-node and blacksilk-miner binaries.
    #[arg(long)]
    bin_dir: PathBuf,
    /// Output directory (data, logs, metrics, summary). Must not exist.
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value_t = 5)]
    nodes: usize,
    #[arg(long, default_value_t = 180)]
    duration_mins: u64,
    #[arg(long, default_value_t = 80)]
    latency_ms: u64,
    #[arg(long, default_value_t = 60)]
    jitter_ms: u64,
    #[arg(long, default_value_t = 25)]
    partition_every_mins: u64,
    #[arg(long, default_value_t = 4)]
    partition_mins: u64,
    #[arg(long, default_value_t = 20)]
    tx_every_secs: u64,
    #[arg(long, default_value_t = 41000)]
    base_port: u16,
    #[arg(long, default_value_t = 1)]
    miner_threads: usize,
    /// regtest (10-second blocks) or testnet (the real testnet rules, 120 s blocks).
    #[arg(long, default_value = "regtest")]
    network: String,
}

fn rpc_port(base: u16, i: usize) -> u16 {
    base + 20 * i as u16
}
fn p2p_port(base: u16, i: usize) -> u16 {
    base + 20 * i as u16 + 1
}
fn proxy_port(base: u16, from: usize, to: usize) -> u16 {
    base + 2000 + 40 * from as u16 + to as u16
}
fn local(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

struct Link {
    from: usize,
    to: usize,
    handle: proxy::LinkHandle,
}

#[derive(Default, Serialize)]
struct Report {
    started_unix: u64,
    duration_secs: u64,
    nodes: usize,
    final_height: u64,
    partitions: u32,
    tx_attempts: u32,
    tx_submitted: u32,
    tx_failures: BTreeMap<String, u32>,
    reorganizations: u32,
    max_reorg_depth: u64,
    misbehavior_disconnects: u32,
    crashes: Vec<String>,
    network: String,
    /// Samples in which all nodes had the same tip (the rest caught a block in flight).
    all_equal_samples: u32,
    /// A node stayed on a stale tip for more than 90 s while connected and behind.
    stuck_incidents: u32,
    samples: u32,
    max_rss_mb: BTreeMap<String, f64>,
    converged_at_end: bool,
    mempools_drained_at_end: bool,
    late_joiner_synced: bool,
    late_joiner_peers: usize,
    fresh_wallet_balances_match: bool,
    supply_conserved: bool,
    generated: u64,
    wallet_total: u64,
    proxy_bytes: u64,
    checks_passed: bool,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn log(out: &mut File, msg: &str) {
    let line = format!("[{}] {msg}", unix_now());
    println!("{line}");
    let _ = writeln!(out, "{line}");
}

/// Resident memory of a process in MB (Windows: tasklist, Linux: /proc).
fn rss_mb(pid: u32) -> Option<f64> {
    if cfg!(windows) {
        let o = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&o.stdout);
        let field = s.split("\",\"").nth(4)?;
        let kb: f64 = field
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .ok()?;
        Some(kb / 1024.0)
    } else {
        let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let line = s.lines().find(|l| l.starts_with("VmRSS:"))?;
        let kb: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kb / 1024.0)
    }
}

struct Proc {
    name: String,
    child: Child,
}

fn spawn(bin: &Path, args: &[String], log_path: &Path, name: &str) -> Proc {
    let f = File::create(log_path).expect("log file");
    let child = Command::new(bin)
        .args(args)
        .stdout(Stdio::from(f.try_clone().expect("dup")))
        .stderr(Stdio::from(f))
        .spawn()
        .unwrap_or_else(|e| panic!("starting {}: {e}", bin.display()));
    Proc {
        name: name.into(),
        child,
    }
}

fn wait_rpc(port: u16, secs: u64) -> bool {
    let c = Client::new(&local(port).to_string());
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if c.info().is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

fn infos(clients: &[Client]) -> Vec<Option<Info>> {
    clients.iter().map(|c| c.info().ok()).collect()
}

fn node_args(
    a: &Args,
    i: usize,
    data: &Path,
    peers: &[SocketAddr],
    max_outbound: usize,
    connect_only: bool,
) -> Vec<String> {
    let mut v = vec![
        "--network".into(),
        a.network.clone(),
        "--allow-private".into(),
        "--data-dir".into(),
        data.display().to_string(),
        "--rpc-bind".into(),
        local(rpc_port(a.base_port, i)).to_string(),
        "--p2p-bind".into(),
        local(p2p_port(a.base_port, i)).to_string(),
        "--max-outbound".into(),
        max_outbound.to_string(),
        "--no-builtin-seeds".into(),
    ];
    for p in peers {
        v.push("--peer".into());
        v.push(p.to_string());
    }
    // Lab links must stay the proxied ones so partitions are complete; discovery
    // is exercised separately by the late joiner.
    if connect_only {
        v.push("--connect-only".into());
    }
    v
}

fn main() {
    let a = Args::parse();
    assert!(a.nodes >= 4, "need at least 4 nodes");
    assert!(
        !a.out.exists(),
        "{} exists; choose a new output directory",
        a.out.display()
    );
    std::fs::create_dir_all(&a.out).unwrap();
    let mut journal = File::create(a.out.join("journal.log")).unwrap();
    let mut metrics = File::create(a.out.join("metrics.csv")).unwrap();
    writeln!(
        metrics,
        "unix,partitioned,heights,header_heights,tips,mempools,peers,rss_mb"
    )
    .unwrap();
    let node_bin = a.bin_dir.join(if cfg!(windows) {
        "blacksilk-node.exe"
    } else {
        "blacksilk-node"
    });
    let miner_bin = a.bin_dir.join(if cfg!(windows) {
        "blacksilk-miner.exe"
    } else {
        "blacksilk-miner"
    });
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut report = Report {
        started_unix: unix_now(),
        nodes: a.nodes,
        ..Default::default()
    };
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    let mut rng = ChaCha20Rng::from_seed(seed);
    let n = a.nodes;
    let group = |i: usize| usize::from(i >= n / 2);

    // Links: ring plus chords (i -> i+1, i -> i+2), each through a proxy.
    let mut links = Vec::new();
    for i in 0..n {
        for d in [1, 2] {
            let j = (i + d) % n;
            let h = rt
                .block_on(proxy::start(
                    local(proxy_port(a.base_port, i, j)),
                    local(p2p_port(a.base_port, j)),
                    Duration::from_millis(a.latency_ms),
                    a.jitter_ms,
                ))
                .expect("proxy bind");
            links.push(Link {
                from: i,
                to: j,
                handle: h,
            });
        }
    }

    // Nodes.
    let mut procs: Vec<Proc> = Vec::new();
    for i in 0..n {
        let peers: Vec<SocketAddr> = links
            .iter()
            .filter(|l| l.from == i)
            .map(|l| local(proxy_port(a.base_port, l.from, l.to)))
            .collect();
        let data = a.out.join(format!("node{i}"));
        let args = node_args(&a, i, &data, &peers, peers.len(), true);
        procs.push(spawn(
            &node_bin,
            &args,
            &a.out.join(format!("node{i}.log")),
            &format!("node{i}"),
        ));
    }
    for i in 0..n {
        assert!(
            wait_rpc(rpc_port(a.base_port, i), 60),
            "node{i} did not start"
        );
    }
    let clients: Vec<Client> = (0..n)
        .map(|i| Client::new(&local(rpc_port(a.base_port, i)).to_string()))
        .collect();
    log(&mut journal, &format!("{n} nodes up"));

    // Wallets: two miners (one per partition group) and three users.
    let net = match a.network.as_str() {
        "regtest" => Network::Regtest,
        "testnet" => Network::Testnet,
        other => panic!("unsupported network {other}"),
    };
    report.network = a.network.clone();
    let rules = TxRules::for_chain(&ChainParams::for_network(net));
    let mut wallets: Vec<(String, Wallet)> = Vec::new();
    for name in ["miner-a", "miner-b", "user-1", "user-2", "user-3"] {
        wallets.push((name.into(), Wallet::generate(net, 1).unwrap()));
    }
    let miner_nodes = [0, n / 2];
    for (k, &node) in miner_nodes.iter().enumerate() {
        let addr = wallets[k].1.address(0, 0);
        let args: Vec<String> = vec![
            "--node".into(),
            local(rpc_port(a.base_port, node)).to_string(),
            "--light".into(),
            "--threads".into(),
            a.miner_threads.to_string(),
            "--refresh".into(),
            "5".into(),
            "--address".into(),
            addr,
        ];
        procs.push(spawn(
            &miner_bin,
            &args,
            &a.out.join(format!("miner{k}.log")),
            &format!("miner{k}"),
        ));
    }
    log(
        &mut journal,
        "miners started on nodes 0 and n/2 (one per partition group)",
    );

    // Main loop.
    let start = Instant::now();
    let end = start + Duration::from_secs(a.duration_mins * 60);
    let mut next_sample = start;
    let mut next_tx = start + Duration::from_secs(60);
    let mut partition_until: Option<Instant> = None;
    let mut next_partition = start + Duration::from_secs(a.partition_every_mins * 60);
    let mut connected_since = start;
    // Since when each node has been continuously behind the best height (None: not behind).
    let mut behind_since: Vec<Option<Instant>> = vec![None; n];
    let mut stuck_now: Vec<bool> = vec![false; n];
    while Instant::now() < end {
        let now = Instant::now();

        // Partitions.
        if partition_until.is_none() && now >= next_partition {
            for l in &links {
                if group(l.from) != group(l.to) {
                    l.handle.set_up(false);
                }
            }
            partition_until = Some(now + Duration::from_secs(a.partition_mins * 60));
            report.partitions += 1;
            log(
                &mut journal,
                &format!(
                    "partition #{} started (groups split at node {})",
                    report.partitions,
                    n / 2
                ),
            );
        }
        if partition_until.is_some_and(|t| now >= t) {
            for l in &links {
                l.handle.set_up(true);
            }
            partition_until = None;
            connected_since = now;
            next_partition = now + Duration::from_secs(a.partition_every_mins * 60);
            log(&mut journal, "partition healed");
        }

        // Samples and invariants.
        if now >= next_sample {
            next_sample = now + Duration::from_secs(15);
            report.samples += 1;
            let is = infos(&clients);
            let heights: Vec<String> = is
                .iter()
                .map(|i| i.as_ref().map_or("-".into(), |i| i.height.to_string()))
                .collect();
            let hh: Vec<String> = is
                .iter()
                .map(|i| {
                    i.as_ref()
                        .map_or("-".into(), |i| i.header_height.to_string())
                })
                .collect();
            let tips: Vec<String> = is
                .iter()
                .map(|i| i.as_ref().map_or("-".into(), |i| i.tip[..8].to_string()))
                .collect();
            let mps: Vec<String> = is
                .iter()
                .map(|i| i.as_ref().map_or("-".into(), |i| i.mempool_txs.to_string()))
                .collect();
            let peers: Vec<String> = is
                .iter()
                .map(|i| i.as_ref().map_or("-".into(), |i| i.peers.to_string()))
                .collect();
            let mut rss = Vec::new();
            for p in &mut procs {
                if let Ok(Some(status)) = p.child.try_wait() {
                    let msg = format!("{} exited: {status}", p.name);
                    if !report.crashes.contains(&msg) {
                        log(&mut journal, &format!("CRASH: {msg}"));
                        report.crashes.push(msg);
                    }
                }
                let mb = rss_mb(p.child.id()).unwrap_or(0.0);
                let e = report.max_rss_mb.entry(p.name.clone()).or_insert(0.0);
                *e = e.max(mb);
                rss.push(format!("{mb:.0}"));
            }
            let partitioned = partition_until.is_some();
            let all_equal = is
                .iter()
                .all(|i| i.as_ref().map(|x| &x.tip) == is[0].as_ref().map(|x| &x.tip));
            report.all_equal_samples += all_equal as u32;
            // A node is stuck if, while the network is connected, it stays behind the
            // best height for more than 90 s. Briefly trailing while a block
            // propagates is normal and not counted.
            let best = is.iter().flatten().map(|x| x.height).max().unwrap_or(0);
            let connected_long =
                !partitioned && now.duration_since(connected_since) > Duration::from_secs(120);
            for (k, info) in is.iter().enumerate() {
                let Some(info) = info else { continue };
                if info.height >= best || !connected_long {
                    behind_since[k] = None;
                    stuck_now[k] = false;
                    continue;
                }
                let since = *behind_since[k].get_or_insert(now);
                if now.duration_since(since) > Duration::from_secs(90) && !stuck_now[k] {
                    stuck_now[k] = true;
                    report.stuck_incidents += 1;
                    log(
                        &mut journal,
                        &format!(
                            "node{k} stuck at height {} while best is {best}",
                            info.height
                        ),
                    );
                }
            }
            let _ = writeln!(
                metrics,
                "{},{},{},{},{},{},{},{}",
                unix_now(),
                partitioned,
                heights.join("/"),
                hh.join("/"),
                tips.join("/"),
                mps.join("/"),
                peers.join("/"),
                rss.join("/")
            );
            let _ = metrics.flush();
        }

        // Transactions.
        if now >= next_tx {
            next_tx = now + Duration::from_secs(a.tx_every_secs);
            let from = (rng.next_u32() as usize) % wallets.len();
            let node = (rng.next_u32() as usize) % n;
            let mut to = (rng.next_u32() as usize) % wallets.len();
            if to == from {
                to = (to + 1) % wallets.len();
            }
            let dest_str = wallets[to].1.address(0, rng.next_u32() % 4);
            let dest = blacksilk_chain::address::decode_address(net, &dest_str).unwrap();
            let amount = COIN / 10 + rng.next_u64() % COIN;
            let (name, w) = &mut wallets[from];
            let name = name.clone();
            match w.sync(&clients[node]) {
                Ok(_) if w.balance().unlocked > amount + COIN => {
                    report.tx_attempts += 1;
                    match w.transfer(&clients[node], &dest, amount, &rules, &mut rng) {
                        Ok(_) => {
                            report.tx_submitted += 1;
                        }
                        Err(e) => {
                            let key = format!("{e}").split(':').next().unwrap_or("?").to_string();
                            *report.tx_failures.entry(key).or_insert(0) += 1;
                            log(
                                &mut journal,
                                &format!("tx from {name} via node{node} failed: {e}"),
                            );
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => log(&mut journal, &format!("sync {name} via node{node}: {e}")),
            }
            // Unconfirmed spends expire inside the wallet (20 blocks); the harness
            // never clears them itself.
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    log(&mut journal, "traffic phase over; final checks");

    // --- Final checks -----------------------------------------------------------
    for l in &links {
        l.handle.set_up(true);
    }
    // Convergence (tips equal) and drained mempools (miners keep mining).
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut converged = false;
    let mut drained = false;
    while Instant::now() < deadline {
        let is = infos(&clients);
        converged = is.iter().all(|i| i.is_some())
            && is
                .iter()
                .all(|i| i.as_ref().map(|x| &x.tip) == is[0].as_ref().map(|x| &x.tip));
        drained = is
            .iter()
            .all(|i| i.as_ref().is_some_and(|x| x.mempool_txs == 0));
        if converged && drained {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    report.converged_at_end = converged;
    report.mempools_drained_at_end = drained;
    // Stop the miners, then take a stable snapshot.
    for p in procs.iter_mut().filter(|p| p.name.starts_with("miner")) {
        let _ = p.child.kill();
    }
    std::thread::sleep(Duration::from_secs(20));
    let final_info = clients[0].info().ok();
    report.final_height = final_info.as_ref().map_or(0, |i| i.height);
    report.generated = final_info.as_ref().map_or(0, |i| i.generated);
    log(
        &mut journal,
        &format!(
            "converged={converged} drained={drained} height={}",
            report.final_height
        ),
    );

    // Late joiner: one direct peer (node 0), discovers the rest through Addr.
    let late = n;
    let data = a.out.join("node-late");
    let args = node_args(
        &a,
        late,
        &data,
        &[local(p2p_port(a.base_port, 0))],
        4,
        false,
    );
    procs.push(spawn(
        &node_bin,
        &args,
        &a.out.join("node-late.log"),
        "node-late",
    ));
    assert!(wait_rpc(rpc_port(a.base_port, late), 60));
    let late_client = Client::new(&local(rpc_port(a.base_port, late)).to_string());
    let deadline = Instant::now() + Duration::from_secs(900);
    while Instant::now() < deadline {
        if let (Ok(li), Some(fi)) = (late_client.info(), &final_info) {
            if li.tip == fi.tip && li.peers >= 2 {
                report.late_joiner_synced = true;
                report.late_joiner_peers = li.peers;
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    log(
        &mut journal,
        &format!(
            "late joiner synced={} peers={}",
            report.late_joiner_synced, report.late_joiner_peers
        ),
    );

    // Fresh wallets from seed against the late node vs. long-running wallets.
    let mut all_match = true;
    let mut total = 0u64;
    for (name, w) in &mut wallets {
        let _ = w.sync(&clients[0]);
        w.clear_pending();
        let mut fresh = Wallet::from_mnemonic(net, &w.mnemonic(), 1).unwrap();
        for i in 0..4 {
            fresh.address(0, i);
        }
        let fresh_ok = fresh.sync(&late_client).is_ok();
        let (b1, b2) = (w.balance(), fresh.balance());
        total += b1.total;
        let ok = fresh_ok && b1.total == b2.total;
        all_match &= ok;
        log(
            &mut journal,
            &format!(
                "{name}: balance {} (fresh restore: {}) {}",
                format_amount(b1.total),
                format_amount(b2.total),
                if ok { "OK" } else { "MISMATCH" }
            ),
        );
    }
    report.fresh_wallet_balances_match = all_match;
    report.wallet_total = total;
    report.supply_conserved = total == report.generated;
    log(
        &mut journal,
        &format!(
            "supply: generated {} vs wallets {}",
            format_amount(report.generated),
            format_amount(total)
        ),
    );

    for p in &mut procs {
        let _ = p.child.kill();
    }
    // Log analysis.
    for entry in std::fs::read_dir(&a.out).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !(name.starts_with("node") && name.ends_with(".log")) {
            continue;
        }
        let text = std::fs::read_to_string(entry.path()).unwrap_or_default();
        for line in text.lines() {
            if let Some(rest) = line.split("reorganization: disconnecting ").nth(1) {
                report.reorganizations += 1;
                let depth: u64 = rest
                    .split_whitespace()
                    .next()
                    .and_then(|d| d.parse().ok())
                    .unwrap_or(0);
                report.max_reorg_depth = report.max_reorg_depth.max(depth);
            }
            if line.contains("for misbehavior") {
                report.misbehavior_disconnects += 1;
            }
        }
    }
    report.proxy_bytes = links
        .iter()
        .map(|l| l.handle.bytes.load(std::sync::atomic::Ordering::Relaxed))
        .sum();
    report.duration_secs = start.elapsed().as_secs();
    report.checks_passed = report.crashes.is_empty()
        && report.converged_at_end
        && report.mempools_drained_at_end
        && report.late_joiner_synced
        && report.fresh_wallet_balances_match
        && report.supply_conserved
        && report.misbehavior_disconnects == 0
        && report.stuck_incidents == 0;
    let json = serde_json::to_string_pretty(&report).unwrap();
    std::fs::write(a.out.join("summary.json"), &json).unwrap();
    println!("{json}");
    rt.shutdown_background();
    std::process::exit(if report.checks_passed { 0 } else { 1 });
}
