//! The network manager (docs/p2p.md): connections, handshake, message handling,
//! header-first sync, block and transaction relay, Dandelion++, peer management.
//!
//! Concurrency rules:
//! - the chain lock (`ChainManager`) and the network state lock are never held
//!   at the same time, and neither is held across an `.await`;
//! - the chain lock is never taken on an async worker thread: every access goes
//!   through a blocking thread (`Inner::with_chain`, `spawn_blocking`), so a
//!   long lock hold elsewhere never stalls pings, reads or accepts (R8-1);
//! - block bodies are connected by the block worker in bounded steps
//!   (`submit_block_in_steps`), releasing the chain lock in between;
//! - a poisoned chain or state lock stops the node (`lock_or_exit`).

mod addr_relay;
mod admission;
mod blocks;
mod config;
mod conn;
mod dispatch;
mod headers;
mod maintenance;
mod peers;
mod relay;
mod state;
mod stem;

use crate::addr::NetAddr;
use crate::addrman::{AddrMan, BanList};
use crate::dandelion::Dandelion;
use crate::originated::Originated;
use blacksilk_chain::manager::ChainManager;
use blacksilk_consensus::Hash;
use blacksilk_tx::types::Transaction;
use blocks::block_worker;
pub use blocks::BLOCK_WINDOW_BYTES;
pub use config::{NetConfig, NetStats, PeerInfo};
use headers::header_worker;
use maintenance::maintenance_loop;
use peers::{accept_loop, connect_outbound};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use state::{Inner, State};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard};
use stem::{submit_local, ORIGINATED_FILE};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

pub type SharedChain = Arc<Mutex<ChainManager>>;

/// Exit status of a node whose chain or network-state lock was poisoned by a
/// panic (the same as `blacksilk_node::POISONED_EXIT_CODE`).
pub const POISONED_EXIT_CODE: i32 = 70;

/// Locks `m`, or stops the process if a panic poisoned it (R10-2). A panic
/// while holding the chain lock can leave the manager half-updated (a block
/// applied to the state without being connected, for example); continuing
/// would relay and build on that state. The block store is append-only and a
/// restart replays it deterministically, so the node exits instead, with
/// [`POISONED_EXIT_CODE`], for the supervisor to restart it.
pub fn lock_or_exit<'a, T>(m: &'a Mutex<T>, what: &str) -> MutexGuard<'a, T> {
    match m.lock() {
        Ok(guard) => guard,
        Err(_) => fatal(&format!("{what} lock poisoned by a panic")),
    }
}

/// Logs `why` and exits with [`POISONED_EXIT_CODE`].
fn fatal(why: &str) -> ! {
    log::error!("{why}; stopping (restart to recover: the block store is replayed)");
    // Also without a logger (tests, embedders): the exit must not be silent.
    eprintln!("blacksilk-p2p: {why}; exiting with status {POISONED_EXIT_CODE}");
    std::process::exit(POISONED_EXIT_CODE)
}

/// Handle to the running network.
#[derive(Clone)]
pub struct Network {
    inner: Arc<Inner>,
}

impl Network {
    /// Binds the listener (if configured) and starts the network tasks.
    pub async fn start(cfg: NetConfig, chain: SharedChain) -> std::io::Result<Network> {
        if cfg.proxy_only && cfg.proxy.is_none() {
            return Err(std::io::Error::other("proxy_only requires a proxy"));
        }
        match &cfg.public_address {
            Some(a) if a.is_onion() && !cfg.proxy_only => log::warn!(
                "public address {a} is an onion but the node also uses clearnet: it is advertised only over Tor connections"
            ),
            Some(a) if !a.is_onion() && cfg.proxy.is_some() => log::warn!(
                "public address {a} is clearnet but outbound connections use a proxy: it is not advertised over proxied connections"
            ),
            _ => {}
        }
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut rng = ChaCha20Rng::from_seed(seed);
        let addrman = cfg
            .data_dir
            .as_ref()
            .and_then(|d| AddrMan::load(&d.join("peers.json")))
            .unwrap_or_else(|| AddrMan::new(&mut rng));
        let bans = cfg
            .data_dir
            .as_ref()
            .map(|d| BanList::load(&d.join("bans.json")))
            .unwrap_or_default();
        // Transactions originated before a restart are not originated again
        // while other nodes may still hold them (docs/p2p.md §8.1).
        let originated = cfg
            .data_dir
            .as_ref()
            .map(|d| Originated::load(&d.join(ORIGINATED_FILE)))
            .unwrap_or_default();
        let listener = match cfg.listen {
            Some(a) => Some(TcpListener::bind(a).await?),
            None => None,
        };
        let local_addr = listener.as_ref().and_then(|l| l.local_addr().ok());
        let (tip, genesis_id) = {
            let chain = chain.clone();
            tokio::task::spawn_blocking(move || {
                let c = lock_or_exit(&chain, "chain");
                (c.tip_id(), c.params().genesis_id())
            })
            .await
            .map_err(std::io::Error::other)?
        };
        let state = State {
            peers: HashMap::new(),
            addrman,
            bans,
            dandelion: Dandelion::new(cfg.dandelion.clone()),
            stempool: HashMap::new(),
            stem_key_images: HashMap::new(),
            px_global: crate::limits::TokenBucket::new(2.0, 10.0),
            block_requests: HashMap::new(),
            tx_requests: HashMap::new(),
            tx_announcers: HashMap::new(),
            recent_rejects: VecDeque::new(),
            recent_rejects_set: HashSet::new(),
            late_blocks: HashMap::new(),
            local_nonces: HashSet::new(),
            connecting: HashSet::new(),
            last_attempt: HashMap::new(),
            announced_tip: tip,
            rng,
            misbehaving_disconnects: 0,
            slow_disconnects: 0,
            bans_dirty: false,
            handshaking: 0,
            handshaking_ip: HashMap::new(),
            header_queue_len: 0,
            header_queue_origin: HashMap::new(),
            ctx_rejects: HashSet::new(),
            ctx_rejects_tip: [0; 32],
            tx_verifications: 0,
            px_global_drops: 0,
            unrequested_queued: 0,
            blocks_queued: HashSet::new(),
            upgrades: Default::default(),
            originated,
        };
        let (header_queue, header_rx) = mpsc::unbounded_channel();
        let (block_queue, block_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            chain,
            cfg,
            genesis_id,
            header_queue,
            block_queue,
            state: Mutex::new(state),
            next_id: AtomicU64::new(1),
            local_addr,
            originated_io: Mutex::new(()),
        });
        if let Some(l) = listener {
            tokio::spawn(accept_loop(inner.clone(), l));
        }
        tokio::spawn(maintenance_loop(inner.clone()));
        tokio::spawn(header_worker(inner.clone(), header_rx));
        tokio::spawn(block_worker(inner.clone(), block_rx));
        Ok(Network { inner })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr
    }

    /// Submits a locally created transaction: validated, then sent into the
    /// Dandelion++ stem (docs/p2p.md §8). The only origination path, so the
    /// only one refusing a transaction this node expired recently
    /// (`MempoolError::Expired`, `ChainManager::check_local_tx`) and the only
    /// one consulting the originated set: a transaction originated here
    /// before is never originated again while other nodes may still hold it
    /// (docs/p2p.md §8.1). Peers' transactions are relayed and stemmed
    /// regardless (RTW1B-1).
    ///
    /// `Ok(id)` also when nothing was sent: the transaction is already in
    /// this node's stem, or it was originated here before and is now only
    /// pooled here (held).
    pub async fn submit_tx(&self, tx: Transaction) -> Result<Hash, String> {
        submit_local(&self.inner, tx).await
    }

    pub fn connect(&self, addr: NetAddr) {
        tokio::spawn(connect_outbound(self.inner.clone(), addr));
    }

    pub fn peers(&self) -> Vec<PeerInfo> {
        let st = self.inner.state();
        st.peers
            .iter()
            .map(|(id, p)| PeerInfo {
                id: *id,
                addr: p.addr.clone(),
                inbound: p.inbound,
                height: p.height,
                score: p.score,
                protocol: p.protocol,
            })
            .collect()
    }

    pub fn stats(&self) -> NetStats {
        let st = self.inner.state();
        let outbound = st.peers.values().filter(|p| !p.inbound).count();
        NetStats {
            peers: st.peers.len(),
            outbound,
            inbound: st.peers.len() - outbound,
            stempool: st.stempool.len(),
            banned: st.bans.len(),
            known_addresses: st.addrman.len(),
            misbehaving_disconnects: st.misbehaving_disconnects,
            slow_disconnects: st.slow_disconnects,
            tx_verifications: st.tx_verifications,
            px_global_drops: st.px_global_drops,
        }
    }

    pub fn stempool_contains(&self, id: &Hash) -> bool {
        self.inner.state().stempool.contains_key(id)
    }

    /// Header batches queued for, or under, verification (bounded by
    /// `2 × (max_inbound + max_outbound)`, docs/p2p.md §6).
    pub fn header_queue_len(&self) -> usize {
        self.inner.state().header_queue_len
    }

    /// Whether the operator was warned that peers run a newer consensus
    /// version (once per run; RT-1, RTW1-1, docs/p2p.md §6).
    pub fn upgrade_warned(&self) -> bool {
        self.inner.state().upgrades.warned()
    }

    /// Persists the address table and ban list.
    pub fn save(&self) {
        self.inner.save();
    }
}
