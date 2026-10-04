//! The network manager (docs/p2p.md): connections, handshake, message handling,
//! header-first sync, block and transaction relay, Dandelion++, peer management.
//!
//! Concurrency rules (docs/p2p.md §10):
//! - the chain is reached only through the chain actor
//!   (`blacksilk_chain::actor`, `chain_access`): each access is one command
//!   on a priority lane (Headers, Blocks, Query, Tx), answered through a
//!   oneshot channel, so no async worker and no blocking thread waits for
//!   chain work (R8-1); the actor never takes the network state lock, and no
//!   command is sent with the state lock held (it is never held across an
//!   `.await`);
//! - block bodies are connected by the actor in bounded steps
//!   (`ChainManager::sync_step`), serving one waiting command between two
//!   steps: a header batch or a query waits for at most one step (F34-7);
//! - no connection's read loop and no maintenance tick waits for the chain
//!   (F34-1 to F34-3): messages whose handling needs a command run on the
//!   peer's slow lane (`dispatch::SlowLane`); the handshake, header requests,
//!   tip announcements and download scheduling read the published chain
//!   snapshot (`ChainHandle::summary_cell`); chain-side maintenance (embargo
//!   fluff, pool re-announcement, download scheduling) runs on its own task;
//! - relayed transactions are verified on the actor's Tx lane, below blocks
//!   and headers; when that lane is full they are dropped, never penalized
//!   (F34-5);
//! - a panic in the chain actor, or a poisoned state lock, stops the node
//!   (`POISONED_EXIT_CODE`).

mod addr_relay;
mod admission;
mod blocks;
pub mod chain_access;
mod config;
mod conn;
mod dispatch;
#[cfg(feature = "test-hooks")]
pub mod fuzzing;
mod header_budget;
mod headers;
mod maintenance;
mod peers;
mod relay;
mod serve_tx;
mod state;
mod stem;
mod trickle;
mod tx_requests;

use crate::addr::NetAddr;
use crate::addrman::{AddrMan, BanList};
use crate::clock::{ClockEstimate, ClockMonitor};
use crate::connman::ConnKind;
use crate::dandelion::Dandelion;
use crate::originated::Originated;
use blacksilk_chain::actor::{self, ActorConfig, ChainHandle};
use blacksilk_chain::manager::ChainManager;
use blacksilk_consensus::Hash;
use blacksilk_tx::types::Transaction;
use blocks::block_worker;
pub use blocks::BLOCK_WINDOW_BYTES;
pub use config::{NetConfig, NetStats, PeerInfo};
pub use header_budget::HeaderPowBudget;
use headers::header_worker;
use maintenance::{announce_loop, chain_maintenance_loop, maintenance_loop};
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
use tokio::sync::{mpsc, Notify};

/// A manager behind a lock the caller keeps: the input of [`Network::start`]
/// (tests and embedders), which runs a chain actor over it
/// (`blacksilk_chain::actor::spawn_shared`). The node shares one actor
/// between P2P and RPC instead ([`Network::start_with`]).
pub type SharedChain = Arc<Mutex<ChainManager>>;

/// Exit status of a node whose chain actor panicked or whose network-state
/// lock was poisoned by a panic (the same as
/// `blacksilk_node::POISONED_EXIT_CODE`).
pub const POISONED_EXIT_CODE: i32 = 70;
const _: () = assert!(POISONED_EXIT_CODE == actor::POISONED_EXIT_CODE);

/// Locks `m`, or stops the process if a panic poisoned it (R10-2). A panic
/// while holding a lock (the network state, or a manager lock kept by a
/// test or embedder) can leave its data half-updated (a block applied to the
/// state without being connected, for example); continuing
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
    use std::io::Write as _;
    log::error!("{why}; stopping (restart to recover: the block store is replayed)");
    // Also without a logger (tests, embedders): the exit must not be silent.
    // Written to the process's stderr itself, not with `eprintln!`: the test
    // harness captures `eprintln!` of a test's threads, and the exit below
    // discards that capture unprinted (INV-70).
    let _ = writeln!(
        std::io::stderr(),
        "blacksilk-p2p: {why}; exiting with status {POISONED_EXIT_CODE}"
    );
    std::process::exit(POISONED_EXIT_CODE)
}

/// The network's shared state over the chain actor `chain`, and the
/// receivers of the header and block workers' queues: what
/// [`Network::start_with`] builds, after binding its listeners, before it
/// starts its tasks. The stateful peer fuzz target's harness (`fuzzing`,
/// feature `test-hooks`) builds it the same way.
#[allow(clippy::too_many_arguments)]
fn new_inner(
    cfg: NetConfig,
    chain: ChainHandle,
    rng: ChaCha20Rng,
    addrman: AddrMan,
    bans: BanList,
    originated: Originated,
    local_addr: Option<SocketAddr>,
    onion_addr: Option<SocketAddr>,
) -> (
    Arc<Inner>,
    mpsc::UnboundedReceiver<state::HeaderBatch>,
    mpsc::UnboundedReceiver<state::BlockJob>,
) {
    let summary = chain.summary_cell();
    let genesis_id = summary.load().genesis_id;
    // Entries whose height a damaged originated.json lost start their
    // windows now (docs/p2p.md §8.1): late, never early.
    let mut originated = originated;
    let settled = originated.settle_unknown(summary.load().height + 1);
    if settled > 0 {
        log::error!(
            "{ORIGINATED_FILE}: {settled} entries had lost their height; their windows start now"
        );
    }
    let state = State {
        peers: HashMap::new(),
        addrman,
        bans,
        dandelion: Dandelion::new(cfg.dandelion.clone()),
        stempool: HashMap::new(),
        stem_key_images: HashMap::new(),
        px_global: crate::limits::TokenBucket::new(2.0, 10.0),
        block_requests: HashMap::new(),
        tx_tracker: Default::default(),
        inbound_trickle: Default::default(),
        owed: HashMap::new(),
        recent_rejects: VecDeque::new(),
        recent_rejects_set: HashSet::new(),
        late_blocks: HashMap::new(),
        local_nonces: HashSet::new(),
        connecting: HashMap::new(),
        last_attempt: HashMap::new(),
        rng,
        misbehaving_disconnects: 0,
        slow_disconnects: 0,
        transport_failures: 0,
        bans_dirty: false,
        handshakes: HashMap::new(),
        handshaking_ip: HashMap::new(),
        next_handshake: 0,
        header_queue_len: 0,
        header_queue_origin: HashMap::new(),
        header_queue_untrusted: 0,
        header_pow: header_budget::PowBudget::new(&cfg.header_pow_budget),
        ctx_rejects: HashSet::new(),
        ctx_rejects_tip: [0; 32],
        tx_verifications: 0,
        px_global_drops: 0,
        tx_lane_drops: 0,
        px_global_taken: 0,
        unrequested_queued: 0,
        blocks_queued: HashSet::new(),
        upgrades: Default::default(),
        originated,
        connman: Default::default(),
    };
    let (header_queue, header_rx) = mpsc::unbounded_channel();
    let (block_queue, block_rx) = mpsc::unbounded_channel();
    // Woken on every published tip change (RT-LAB F2).
    let tip_published = Arc::new(Notify::new());
    {
        let n = tip_published.clone();
        summary.on_tip_change(move || n.notify_one());
    }
    let inner = Arc::new(Inner {
        chain,
        summary,
        cfg,
        genesis_id,
        header_queue,
        header_wake: Notify::new(),
        block_queue,
        state: Mutex::new(state),
        next_id: AtomicU64::new(1),
        local_addr,
        onion_addr,
        originated_io: Mutex::new(()),
        clock: Mutex::new(ClockMonitor::default()),
        tip_published,
        serve_budget: Default::default(),
        maintenance_seen: AtomicU64::new(0),
    });
    (inner, header_rx, block_rx)
}

/// Handle to the running network.
#[derive(Clone)]
pub struct Network {
    inner: Arc<Inner>,
}

impl Network {
    /// [`Self::start_with`] over a chain actor started on `chain` (tests and
    /// embedders that keep the manager's lock to read it directly). The
    /// actor runs until the network's tasks end.
    pub async fn start(cfg: NetConfig, chain: SharedChain) -> std::io::Result<Network> {
        let (handle, _thread) = actor::spawn_shared(chain, ActorConfig::default());
        Self::start_with(cfg, handle).await
    }

    /// Binds the listener (if configured) and starts the network tasks, with
    /// every chain access going to the chain actor behind `chain`.
    pub async fn start_with(cfg: NetConfig, chain: ChainHandle) -> std::io::Result<Network> {
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
        let mut addrman = cfg
            .data_dir
            .as_ref()
            .and_then(|d| AddrMan::load_grouped(&d.join("peers.json"), cfg.allow_private))
            .unwrap_or_else(|| AddrMan::new(&mut rng));
        addrman.set_private_groups(cfg.allow_private);
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
        let onion_listener = match cfg.onion_listen {
            Some(a) => Some(TcpListener::bind(a).await?),
            None => None,
        };
        let onion_addr = onion_listener.as_ref().and_then(|l| l.local_addr().ok());
        let local_addr = listener.as_ref().and_then(|l| l.local_addr().ok());
        let (inner, header_rx, block_rx) = new_inner(
            cfg, chain, rng, addrman, bans, originated, local_addr, onion_addr,
        );
        if let Some(l) = listener {
            tokio::spawn(accept_loop(inner.clone(), l, false));
        }
        if let Some(l) = onion_listener {
            tokio::spawn(accept_loop(inner.clone(), l, true));
        }
        tokio::spawn(announce_loop(inner.clone()));
        tokio::spawn(maintenance_loop(inner.clone()));
        tokio::spawn(trickle::trickle_loop(inner.clone()));
        tokio::spawn(chain_maintenance_loop(inner.clone()));
        tokio::spawn(header_worker(inner.clone(), header_rx));
        tokio::spawn(block_worker(inner.clone(), block_rx));
        Ok(Network { inner })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr
    }

    /// The onion listener's address (`NetConfig::onion_listen`), if any.
    pub fn onion_local_addr(&self) -> Option<SocketAddr> {
        self.inner.onion_addr
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

    /// Dials `addr` as a full-relay outbound peer.
    pub fn connect(&self, addr: NetAddr) {
        tokio::spawn(connect_outbound(
            self.inner.clone(),
            addr,
            ConnKind::FullRelay,
        ));
    }

    pub fn peers(&self) -> Vec<PeerInfo> {
        let st = self.inner.state();
        st.peers
            .iter()
            .map(|(id, p)| PeerInfo {
                id: *id,
                addr: p.addr.clone(),
                inbound: p.inbound,
                kind: p.kind,
                height: p.height,
                score: p.score,
                protocol: p.protocol,
                min_ping: p.min_ping,
                last_block: p.last_block,
                last_tx: p.last_tx,
            })
            .collect()
    }

    pub fn stats(&self) -> NetStats {
        let st = self.inner.state();
        let outbound = st.peers.values().filter(|p| !p.inbound).count();
        NetStats {
            peers: st.peers.len(),
            outbound,
            block_relay: st
                .peers
                .values()
                .filter(|p| p.kind == ConnKind::BlockRelay)
                .count(),
            inbound: st.peers.len() - outbound,
            stempool: st.stempool.len(),
            banned: st.bans.len(),
            known_addresses: st.addrman.len(),
            misbehaving_disconnects: st.misbehaving_disconnects,
            slow_disconnects: st.slow_disconnects,
            transport_failures: st.transport_failures,
            tx_verifications: st.tx_verifications,
            px_global_drops: st.px_global_drops,
            tx_lane_drops: st.tx_lane_drops,
            px_global_taken: st.px_global_taken,
            header_pow_failed: st.header_pow.failed,
            header_pow_throttled: st.header_pow.throttled,
        }
    }

    pub fn stempool_contains(&self, id: &Hash) -> bool {
        self.inner.state().stempool.contains_key(id)
    }

    /// The next-block height the chain maintenance loop last finished,
    /// pool re-announcement included (tests wait on it instead of on
    /// time; 0 before its first look).
    #[doc(hidden)]
    pub fn maintenance_seen_height(&self) -> u64 {
        self.inner
            .maintenance_seen
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Queues an announcement of `id` to every transaction-relaying peer, as
    /// for a newly pooled transaction (tests of the trickle's timing).
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn announce_for_tests(&self, id: Hash) {
        self.inner.announce_tx(id, None);
    }

    /// Announcements queued for the trickle, over all peers (tests: once 0,
    /// every queued `InvTx` is in an outbox).
    #[doc(hidden)]
    pub fn queued_announcements(&self) -> usize {
        self.inner
            .state()
            .peers
            .values()
            .map(|p| p.inv_queue.len())
            .sum()
    }

    /// The current Dandelion epoch's stem peers (tests: a stem peer is
    /// never dropped by an honest burst, TM2-17).
    #[doc(hidden)]
    pub fn stem_peers(&self) -> Vec<crate::dandelion::PeerId> {
        self.inner.state().dandelion.stems().to_vec()
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

    /// The local clock's offset against recent blocks, once enough blocks
    /// from enough peers were seen (`crate::clock`, docs/p2p.md §6.1): for
    /// the operator only, never used for validation, never sent to a peer.
    pub fn clock_estimate(&self) -> Option<ClockEstimate> {
        self.inner.clock().estimate()
    }

    /// Persists the address table and ban list, and the anchors: call at
    /// shutdown (the anchors file is written only here, docs/p2p.md §9).
    pub fn save(&self) {
        self.inner.save();
        peers::save_anchors(&self.inner);
    }
}
