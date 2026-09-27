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

use crate::addr::NetAddr;
use crate::addrman::{AddrMan, BanList};
use crate::dandelion::{exponential, Dandelion, DandelionParams, PeerId, Route, Source};
use crate::limits::{score, PeerLimits, BAN_SECS, BAN_THRESHOLD};
use crate::message::{
    is_known_type, Message, Version, MAX_HEADERS, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION,
};
use crate::socks5;
use crate::transport::{handshake, FrameReader, FrameWriter, TransportError};
use blacksilk_chain::block::{Block, MAX_BLOCK_BYTES};
use blacksilk_chain::manager::{
    submit_block_in_steps, ChainManager, SubmitError, SYNC_STEP_BLOCKS,
};
use blacksilk_chain::mempool::MempoolError;
use blacksilk_consensus::{BlockHeader, Hash, HeaderChain, HeaderError};
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify};

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

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const PING_INTERVAL: Duration = Duration::from_secs(60);
const PONG_TIMEOUT: Duration = Duration::from_secs(30);
const BLOCK_TIMEOUT: Duration = Duration::from_secs(60);
const TX_TIMEOUT: Duration = Duration::from_secs(30);
const HEADERS_TIMEOUT: Duration = Duration::from_secs(60);
/// Block requests in flight per peer (count cap). A block counts from its
/// request until it has been processed (connected or rejected), so the queue
/// of the block worker is bounded by the peers' windows.
const BLOCKS_IN_FLIGHT: usize = 16;
/// Bytes in flight per peer (R8-9): headers carry no body size, so each
/// request is charged `MAX_BLOCK_BYTES`; at most this many bytes' worth of
/// blocks are requested from one peer at a time (3 maximum-size blocks), so a
/// peer on a slow link is not asked for more than it can deliver before the
/// block timeout. One block is always allowed.
pub const BLOCK_WINDOW_BYTES: usize = 32 * 1024 * 1024;
const SERVE_BLOCKS_PER_REQUEST: usize = 16;
/// Control messages queued per peer (everything except `Block`).
const OUTBOX: usize = 64;
/// `Block` frames queued per peer; control messages are sent first (R8-11).
const BULK_OUTBOX: usize = 2 * SERVE_BLOCKS_PER_REQUEST;
/// Unrequested blocks queued for the block worker, node-wide. Every one is
/// penalized, and only those whose header we accepted are processed; beyond
/// this they are dropped unread (honest peers send only requested blocks).
const UNREQUESTED_QUEUE: usize = 8;
/// Frames of unknown message types skipped between `Version` and `Verack`
/// (a later protocol version may negotiate features there).
const HANDSHAKE_UNKNOWN_FRAMES: usize = 8;
const RECENT_REJECTS: usize = 10_000;
const ANNOUNCED_CAP: usize = 50_000;
/// Address table and bans are saved at most this often, and only when changed
/// (a crash loses at most this much discovery state).
const SAVE_INTERVAL: Duration = Duration::from_secs(60);
/// A seed is dialed at most this often.
const SEED_RETRY: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct NetConfig {
    pub network_id: u32,
    /// Listen for inbound connections here (`None`: outbound only).
    pub listen: Option<SocketAddr>,
    /// Our reachable address, advertised to peers. `None` keeps it private.
    pub public_address: Option<NetAddr>,
    pub seeds: Vec<NetAddr>,
    /// Peers to keep connected to at all times.
    pub connect: Vec<NetAddr>,
    /// Make outbound connections only to `connect` (no seeds, no discovered
    /// addresses). Inbound connections and address exchange still work.
    pub connect_only: bool,
    /// SOCKS5 proxy for outbound connections (e.g. Tor).
    pub proxy: Option<SocketAddr>,
    /// Only connect through the proxy.
    pub proxy_only: bool,
    pub max_outbound: usize,
    pub max_inbound: usize,
    pub max_per_ip: usize,
    /// Accept and dial loopback/private addresses and skip network-group diversity
    /// (regtest and tests). Loopback peers are then disconnected, not IP-banned.
    pub allow_private: bool,
    /// Where `peers.json` and `bans.json` are kept.
    pub data_dir: Option<PathBuf>,
    pub dandelion: DandelionParams,
    pub trickle_outbound: Duration,
    pub trickle_inbound: Duration,
    pub pow_threads: usize,
    pub tick: Duration,
    /// Per-peer rate limits (docs/p2p.md §10). Tests shrink them.
    pub peer_limits: PeerLimits,
}

impl NetConfig {
    pub fn new(network_id: u32) -> Self {
        Self {
            network_id,
            listen: None,
            public_address: None,
            seeds: Vec::new(),
            connect: Vec::new(),
            connect_only: false,
            proxy: None,
            proxy_only: false,
            max_outbound: 8,
            max_inbound: 64,
            max_per_ip: 2,
            allow_private: false,
            data_dir: None,
            dandelion: DandelionParams::default(),
            trickle_outbound: Duration::from_secs(2),
            trickle_inbound: Duration::from_secs(5),
            pow_threads: std::thread::available_parallelism().map_or(1, |n| n.get()),
            tick: Duration::from_millis(250),
            peer_limits: PeerLimits::default(),
        }
    }
}

/// Public view of a connected peer.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub id: PeerId,
    pub addr: NetAddr,
    pub inbound: bool,
    pub height: u64,
    pub score: u32,
    /// The peer's `Version.protocol`.
    pub protocol: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetStats {
    pub peers: usize,
    pub outbound: usize,
    pub inbound: usize,
    pub stempool: usize,
    pub banned: usize,
    pub known_addresses: (usize, usize),
    /// Peers disconnected for misbehavior since start.
    pub misbehaving_disconnects: u64,
    /// Peers disconnected because they did not read their messages fast enough.
    pub slow_disconnects: u64,
    /// Relayed transactions that reached full verification (signatures,
    /// proofs) since start.
    pub tx_verifications: u64,
    /// PX transactions dropped because the node-wide PX relay limit was
    /// exhausted (docs/p2p.md §10).
    pub px_global_drops: u64,
}

struct Peer {
    addr: NetAddr,
    inbound: bool,
    proxied: bool,
    protocol: u32,
    /// Control messages; sent before anything queued in `bulk`.
    out: mpsc::Sender<Message>,
    /// `Block` frames.
    bulk: mpsc::Sender<Message>,
    kill: Arc<Notify>,
    relay_txs: bool,
    height: u64,
    score: u32,
    limits: PeerLimits,
    answered_getaddr: bool,
    received_addr_batch: bool,
    inv_queue: Vec<Hash>,
    next_inv: Instant,
    announced_to: HashSet<Hash>,
    known_txs: HashSet<Hash>,
    ping: Option<(u64, Instant)>,
    last_ping: Instant,
    last_recv: Instant,
    /// Blocks requested from this peer and not yet processed, and the bytes
    /// charged for them (`MAX_BLOCK_BYTES` each, `BLOCK_WINDOW_BYTES`).
    blocks_in_flight: usize,
    bytes_in_flight: usize,
    headers_requested: Option<Instant>,
    /// When a single header consumed an outstanding `GetHeaders` (it may be a
    /// tip announcement racing the real reply), the request time: one
    /// multi-header batch arriving within `HEADERS_TIMEOUT` of it still counts
    /// as solicited (docs/p2p.md §6).
    headers_grace: Option<Instant>,
    /// A header batch from this peer is queued for, or under, verification by
    /// the header worker. At most one per peer: the queue is bounded by the
    /// number of peers, and the peer is not asked for more headers meanwhile.
    headers_busy: bool,
    /// Headers arrived while `headers_busy`; ask again once the batch is done.
    headers_pending: bool,
    /// The peer sent a header of a version above every version this node's
    /// schedule knows (`HeaderError::UnknownUpgrade`) and the operator was
    /// warned once for it.
    warned_upgrade: bool,
}

struct StemEntry {
    tx: Transaction,
    embargo: Instant,
    /// A local transaction created while there was no stem peer: held here
    /// (not broadcast) until a stem route exists, or until the embargo fires
    /// (docs/p2p.md §8).
    awaiting_stem: bool,
}

struct State {
    peers: HashMap<PeerId, Peer>,
    addrman: AddrMan,
    bans: BanList,
    dandelion: Dandelion,
    stempool: HashMap<Hash, StemEntry>,
    stem_key_images: HashMap<[u8; 32], Hash>,
    /// All peers together: PX verification is expensive, so the node caps the
    /// PX transactions it accepts from the network per second, whatever the
    /// number of peers (docs/px.md §11.5).
    px_global: crate::limits::TokenBucket,
    block_requests: HashMap<Hash, (PeerId, Instant)>,
    tx_requests: HashMap<Hash, (PeerId, Instant)>,
    tx_announcers: HashMap<Hash, VecDeque<PeerId>>,
    recent_rejects: VecDeque<Hash>,
    recent_rejects_set: HashSet<Hash>,
    /// Block requests that timed out, kept for another `BLOCK_TIMEOUT`: the
    /// block arriving late from the peer we asked is an answer, not an
    /// unsolicited block (R8-9).
    late_blocks: HashMap<Hash, (PeerId, Instant)>,
    local_nonces: HashSet<u64>,
    connecting: HashSet<NetAddr>,
    last_attempt: HashMap<NetAddr, Instant>,
    announced_tip: Hash,
    rng: ChaCha20Rng,
    misbehaving_disconnects: u64,
    slow_disconnects: u64,
    /// The ban list changed since it was last saved.
    bans_dirty: bool,
    /// Inbound connections accepted but not yet registered (handshake in
    /// progress), in total and per IP: counted against `max_inbound` and
    /// `max_per_ip` like registered peers.
    handshaking: usize,
    handshaking_ip: HashMap<IpAddr, usize>,
    /// Header batches queued for, or under, verification: in total and per
    /// sender origin (`queue_key`). Bounded (docs/p2p.md §6).
    header_queue_len: usize,
    header_queue_origin: HashMap<NetAddr, usize>,
    /// Transactions that failed a contextual rule at tip `ctx_rejects_tip`
    /// (not verified again until the tip changes; bounded).
    ctx_rejects: HashSet<Hash>,
    ctx_rejects_tip: Hash,
    tx_verifications: u64,
    px_global_drops: u64,
    /// Unrequested blocks in the block worker's queue (`UNREQUESTED_QUEUE`).
    unrequested_queued: usize,
    /// Ids of blocks received and waiting for, or under, processing by the
    /// block worker: not requested again meanwhile.
    blocks_queued: HashSet<Hash>,
}

/// A block waiting for the block worker.
struct BlockJob {
    peer: PeerId,
    block: Block,
    /// Requested from `peer` (it holds a place in the peer's window until
    /// processed); otherwise unrequested (processed only if its header is
    /// known, `UNREQUESTED_QUEUE`).
    requested: bool,
    /// A request that timed out and was answered late: not in the window any
    /// more, but not unsolicited either.
    late: bool,
}

/// A header batch waiting for the header worker, with its sender's address
/// (a sender that disconnects before its batch is verified is still banned).
struct HeaderBatch {
    peer: PeerId,
    addr: NetAddr,
    proxied: bool,
    /// An answer to our `GetHeaders` (not a tip announcement).
    solicited: bool,
    headers: Vec<BlockHeader>,
}

/// The origin a queued header batch is charged to: the sender's IP (port
/// dropped), or the whole address for onion peers.
fn queue_key(addr: &NetAddr) -> NetAddr {
    match addr {
        NetAddr::Ip(a) => NetAddr::Ip(SocketAddr::new(a.ip(), 0)),
        other => other.clone(),
    }
}

/// Remembers transaction ids in a per-peer set, clearing it when it grows past
/// `ANNOUNCED_CAP` (the set only saves redundant announcements; forgetting is
/// harmless, growing without bound is not).
fn remember(set: &mut HashSet<Hash>, ids: impl IntoIterator<Item = Hash>) {
    if set.len() > ANNOUNCED_CAP {
        set.clear();
    }
    set.extend(ids);
}

struct Inner {
    chain: SharedChain,
    cfg: NetConfig,
    /// The chain's genesis id, bound into the session keys (R15-3).
    genesis_id: Hash,
    /// To the header worker (`header_worker`): batches are verified there, one
    /// at a time, never on a peer's read loop.
    header_queue: mpsc::UnboundedSender<HeaderBatch>,
    /// To the block worker (`block_worker`): bodies are validated and
    /// connected there, never on a peer's read loop. Bounded by the peers'
    /// request windows plus `UNREQUESTED_QUEUE`.
    block_queue: mpsc::UnboundedSender<BlockJob>,
    state: Mutex<State>,
    next_id: AtomicU64,
    local_addr: Option<SocketAddr>,
}

/// Handle to the running network.
#[derive(Clone)]
pub struct Network {
    inner: Arc<Inner>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn short(h: &Hash) -> String {
    hex::encode(&h[..6])
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
    /// Dandelion++ stem (docs/p2p.md §8).
    pub async fn submit_tx(&self, tx: Transaction) -> Result<Hash, String> {
        let tx2 = tx.clone();
        let id = self
            .inner
            .with_chain(move |c| c.check_tx(&tx2))
            .await
            .map_err(|e| format!("{e:?}"))?;
        stem_or_fluff(&self.inner, tx, id, Source::Local).await;
        Ok(id)
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

    /// Persists the address table and ban list.
    pub fn save(&self) {
        self.inner.save();
    }
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        lock_or_exit(&self.state, "network state")
    }

    /// The chain lock. Only on blocking threads (`with_chain`, the header and
    /// block workers' blocking tasks), never on an async worker.
    fn chain(&self) -> MutexGuard<'_, ChainManager> {
        lock_or_exit(&self.chain, "chain")
    }

    /// Runs `f` under the chain lock on a blocking thread, so an async worker
    /// never waits for the lock (R8-1). A panic in `f` poisoned the lock: the
    /// node stops, as `lock_or_exit` would on the next access. A task
    /// cancelled because the runtime is shutting down never resolves (the
    /// caller is being dropped too).
    async fn with_chain<T: Send + 'static>(
        self: &Arc<Self>,
        f: impl FnOnce(&mut ChainManager) -> T + Send + 'static,
    ) -> T {
        let inner = self.clone();
        match tokio::task::spawn_blocking(move || f(&mut inner.chain())).await {
            Ok(t) => t,
            Err(e) if e.is_panic() => fatal(&format!("chain task failed: {e}")),
            Err(_) => std::future::pending().await,
        }
    }

    fn save(&self) {
        let Some(dir) = &self.cfg.data_dir else {
            return;
        };
        let st = self.state();
        if let Err(e) = st.addrman.save(&dir.join("peers.json")) {
            log::warn!("saving peers.json: {e}");
        }
        if let Err(e) = st.bans.save(&dir.join("bans.json")) {
            log::warn!("saving bans.json: {e}");
        }
    }

    /// Queues `msg` for `peer`: `Block` frames in the bulk outbox, everything
    /// else in the control outbox, which the writer drains first (R8-11).
    fn send(&self, st: &mut State, peer: PeerId, msg: Message) {
        let Some(p) = st.peers.get(&peer) else { return };
        let queue = if matches!(msg, Message::Block(_)) {
            &p.bulk
        } else {
            &p.out
        };
        if queue.try_send(msg).is_err() {
            // Outbox full: the peer does not read fast enough (or is gone).
            log::debug!("peer {} outbox full; disconnecting", p.addr);
            p.kill.notify_one();
            st.slow_disconnects += 1;
        }
    }

    fn send_now(&self, peer: PeerId, msg: Message) {
        let mut st = self.state();
        self.send(&mut st, peer, msg);
    }

    /// Adds a misbehavior score; at the threshold the peer is disconnected and,
    /// where meaningful, its IP banned (docs/p2p.md §10).
    fn misbehave(&self, peer: PeerId, points: u32, reason: &str) {
        let mut st = self.state();
        self.penalize(&mut st, peer, points, reason);
    }

    /// `misbehave` on a locked state. Returns false if the peer is gone.
    fn penalize(&self, st: &mut State, peer: PeerId, points: u32, reason: &str) -> bool {
        let Some(p) = st.peers.get_mut(&peer) else {
            return false;
        };
        p.score = p.score.saturating_add(points);
        log::debug!(
            "peer {} misbehaved (+{points}, {}): {reason}",
            p.addr,
            p.score
        );
        if p.score < BAN_THRESHOLD {
            return true;
        }
        log::info!("disconnecting peer {} for misbehavior: {reason}", p.addr);
        p.kill.notify_one();
        let (addr, proxied) = (p.addr.clone(), p.proxied);
        st.misbehaving_disconnects += 1;
        self.ban_addr(st, &addr, proxied);
        true
    }

    /// Bans the IP of `addr` (unless it is proxied, or loopback in
    /// `allow_private` mode) and disconnects every live peer from that IP: a
    /// ban must not leave the offender's other connections open.
    fn ban_addr(&self, st: &mut State, addr: &NetAddr, proxied: bool) {
        let Some(ip) = addr.ip() else { return };
        let local = ip.is_loopback() && self.cfg.allow_private;
        if proxied || local {
            return;
        }
        st.bans.ban(ip, unix_now() + BAN_SECS);
        st.bans_dirty = true;
        for p in st.peers.values() {
            if !p.proxied && p.addr.ip() == Some(ip) {
                p.kill.notify_one();
            }
        }
    }

    /// `misbehave` for work that finished after its sender may have
    /// disconnected: a violation worth a ban on its own still bans the address.
    /// One lock for the check and the penalty, so a sender leaving in between
    /// cannot escape the ban.
    fn misbehave_departed(&self, batch: &HeaderBatch, points: u32, reason: &str) {
        let mut st = self.state();
        if self.penalize(&mut st, batch.peer, points, reason) || points < BAN_THRESHOLD {
            return;
        }
        log::info!(
            "banning departed peer {} for misbehavior: {reason}",
            batch.addr
        );
        st.misbehaving_disconnects += 1;
        self.ban_addr(&mut st, &batch.addr, batch.proxied);
    }

    /// Whether a header batch from `addr` may be queued now: at most
    /// `max_per_ip` batches per origin (not enforced for loopback-style
    /// `allow_private` setups, like the connection limit) and
    /// `2 × (max_inbound + max_outbound)` in total.
    fn header_queue_room(&self, st: &State, addr: &NetAddr) -> bool {
        let total = 2 * (self.cfg.max_inbound + self.cfg.max_outbound).max(1);
        if st.header_queue_len >= total {
            return false;
        }
        self.cfg.allow_private
            || st
                .header_queue_origin
                .get(&queue_key(addr))
                .is_none_or(|&n| n < self.cfg.max_per_ip.max(1))
    }

    /// `peer` sent a header whose version no epoch of this node's schedule
    /// uses (`HeaderError::UnknownUpgrade`): not scored, since the peer may run
    /// a newer release that is right. Logged at WARN once per peer, so that the
    /// operator learns an upgrade may be needed.
    fn warn_unknown_upgrade(&self, peer: PeerId, version: u32) {
        let first = {
            let mut st = self.state();
            match st.peers.get_mut(&peer) {
                Some(p) if !p.warned_upgrade => {
                    p.warned_upgrade = true;
                    true
                }
                _ => false,
            }
        };
        if first {
            log::warn!(
                "peer {peer} is on a newer consensus version (header version {version}); \
                 this node may need an upgrade"
            );
        }
    }

    /// Asks `peer` for headers after our best header chain.
    async fn request_headers(self: &Arc<Self>, peer: PeerId) {
        self.request_headers_after(peer, None).await;
    }

    /// Asks `peer` for headers. With `from`, the locator starts at that header
    /// (the last one of the batch the peer just sent), then continues with our
    /// best chain: the peer continues where it stopped even when its branch is
    /// not (yet) our best chain, as for a fork deeper than one batch.
    ///
    /// At most one `GetHeaders` is outstanding per peer: if another task (the
    /// maintenance loop, the header worker) already asked, this does nothing
    /// (the second reply would arrive unsolicited). The request is marked
    /// outstanding, under the same lock as that check, before the locator is
    /// read on a blocking thread.
    async fn request_headers_after(self: &Arc<Self>, peer: PeerId, from: Option<Hash>) {
        {
            let mut st = self.state();
            match st.peers.get_mut(&peer) {
                Some(p) if p.headers_requested.is_none() => {
                    p.headers_requested = Some(Instant::now());
                    p.headers_grace = None;
                    p.headers_pending = false;
                }
                _ => return,
            }
        }
        let mut locator = self.with_chain(|c| c.locator()).await;
        if let Some(id) = from {
            locator.retain(|h| *h != id);
            locator.insert(0, id);
            if locator.len() > crate::message::MAX_LOCATOR as usize {
                // Keep the last entry (genesis): drop the one before it.
                locator.remove(locator.len() - 2);
            }
        }
        let mut st = self.state();
        if let Some(p) = st.peers.get_mut(&peer) {
            p.headers_requested = Some(Instant::now());
            p.headers_grace = None;
            p.headers_pending = false;
        }
        self.send(
            &mut st,
            peer,
            Message::GetHeaders {
                locator,
                stop: [0; 32],
            },
        );
    }

    fn reject_cache(st: &mut State, id: Hash) {
        if st.recent_rejects_set.insert(id) {
            st.recent_rejects.push_back(id);
            if st.recent_rejects.len() > RECENT_REJECTS {
                if let Some(old) = st.recent_rejects.pop_front() {
                    st.recent_rejects_set.remove(&old);
                }
            }
        }
    }

    /// Queues an `InvTx` announcement to every transaction-relaying peer except
    /// `except` and peers that already know it (docs/p2p.md §7).
    fn announce_tx(&self, id: Hash, except: Option<PeerId>) {
        let mut st = self.state();
        let now = Instant::now();
        let (out_mean, in_mean) = (self.cfg.trickle_outbound, self.cfg.trickle_inbound);
        let ids: Vec<PeerId> = st.peers.keys().copied().collect();
        for pid in ids {
            if Some(pid) == except {
                continue;
            }
            let delay = {
                let inbound = st.peers[&pid].inbound;
                exponential(if inbound { in_mean } else { out_mean }, &mut st.rng)
            };
            let p = st.peers.get_mut(&pid).expect("listed");
            if !p.relay_txs || p.known_txs.contains(&id) || p.announced_to.contains(&id) {
                continue;
            }
            if p.inv_queue.is_empty() {
                p.next_inv = now + delay;
            }
            p.inv_queue.push(id);
        }
    }
}

// ---------------------------------------------------------------- connections

async fn accept_loop(inner: Arc<Inner>, listener: TcpListener) {
    loop {
        let (stream, remote) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                log::warn!("accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let addr = NetAddr::Ip(remote);
        let ip = remote.ip();
        let slot = {
            let mut st = inner.state();
            // Connections still in their handshake count like registered
            // ones: otherwise concurrent handshakes bypass both limits.
            let inbound = inbound_count(&st) + st.handshaking;
            let same_ip = same_ip_count(&st, ip) + st.handshaking_ip.get(&ip).copied().unwrap_or(0);
            if st.bans.is_banned(&ip, unix_now())
                || inbound >= inner.cfg.max_inbound
                || (!inner.cfg.allow_private && same_ip >= inner.cfg.max_per_ip)
            {
                continue; // drop the socket
            }
            st.handshaking += 1;
            *st.handshaking_ip.entry(ip).or_default() += 1;
            HandshakeSlot {
                inner: inner.clone(),
                ip,
                released: false,
            }
        };
        let _ = stream.set_nodelay(true);
        tokio::spawn(run_connection(
            inner.clone(),
            stream,
            addr,
            true,
            false,
            Some(slot),
        ));
    }
}

fn inbound_count(st: &State) -> usize {
    st.peers.values().filter(|p| p.inbound).count()
}

/// Registered non-proxied peers from `ip`.
fn same_ip_count(st: &State, ip: IpAddr) -> usize {
    st.peers
        .values()
        .filter(|p| !p.proxied && p.addr.ip() == Some(ip))
        .count()
}

/// An inbound connection's place in the `handshaking` counts, from accept until
/// it is registered or fails. Released under the state lock at registration;
/// otherwise on drop (never dropped while the state lock is held).
struct HandshakeSlot {
    inner: Arc<Inner>,
    ip: IpAddr,
    released: bool,
}

impl HandshakeSlot {
    fn release(&mut self, st: &mut State) {
        if std::mem::replace(&mut self.released, true) {
            return;
        }
        st.handshaking = st.handshaking.saturating_sub(1);
        if let Some(n) = st.handshaking_ip.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                st.handshaking_ip.remove(&self.ip);
            }
        }
    }
}

impl Drop for HandshakeSlot {
    fn drop(&mut self) {
        if !self.released {
            let inner = self.inner.clone();
            let mut st = inner.state();
            self.release(&mut st);
        }
    }
}

async fn connect_outbound(inner: Arc<Inner>, addr: NetAddr) {
    {
        let mut st = inner.state();
        if !st.connecting.insert(addr.clone()) {
            return;
        }
        st.last_attempt.insert(addr.clone(), Instant::now());
    }
    let proxied = inner.cfg.proxy.is_some();
    let result = tokio::time::timeout(CONNECT_TIMEOUT, async {
        match inner.cfg.proxy {
            Some(proxy) => socks5::connect(proxy, &addr).await,
            None => match &addr {
                NetAddr::Ip(a) => TcpStream::connect(a).await,
                NetAddr::Onion { .. } => Err(std::io::Error::other("onion address needs a proxy")),
            },
        }
    })
    .await;
    match result {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            run_connection(inner.clone(), stream, addr.clone(), false, proxied, None).await;
        }
        _ => {
            log::debug!("connect {addr} failed");
            inner.state().addrman.mark_failed(&addr);
        }
    }
    inner.state().connecting.remove(&addr);
}

/// Our address to advertise on a connection (`Version.listen`): an onion
/// address only over Tor (a proxied outbound connection, or an inbound one
/// through our hidden service, which arrives from loopback), a clearnet
/// address only over clearnet. Advertising one over the other would link the
/// node's two identities (I3-2).
fn advertised_listen(
    cfg: &NetConfig,
    addr: &NetAddr,
    inbound: bool,
    proxied: bool,
) -> Option<NetAddr> {
    let public = cfg.public_address.as_ref()?;
    let via_tor = proxied || (inbound && addr.ip().is_some_and(|ip| ip.is_loopback()));
    (public.is_onion() == via_tor).then(|| public.clone())
}

async fn recv_msg<R: AsyncRead + Unpin>(
    r: &mut FrameReader<R>,
    timeout: Duration,
) -> Result<Message, String> {
    let frame = tokio::time::timeout(timeout, r.recv())
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    Message::decode(&frame).map_err(|e| format!("decode: {e:?}"))
}

async fn run_connection<S>(
    inner: Arc<Inner>,
    stream: S,
    addr: NetAddr,
    inbound: bool,
    proxied: bool,
    mut slot: Option<HandshakeSlot>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let nid = inner.cfg.network_id;
    // The session keys also bind the genesis id (R15-3).
    let genesis = inner.genesis_id;
    let (mut reader, mut writer) =
        match handshake(stream, !inbound, nid, &genesis, HANDSHAKE_TIMEOUT).await {
            Ok(x) => x,
            Err(e) => {
                log::debug!("{addr}: transport handshake failed: {e}");
                return;
            }
        };
    // Version exchange.
    let nonce = {
        let mut st = inner.state();
        let n = st.rng.next_u64();
        st.local_nonces.insert(n);
        n
    };
    let (height, tip) = inner
        .with_chain(|c| (c.header_height(), c.best_header_id()))
        .await;
    let ours = Version {
        protocol: PROTOCOL_VERSION,
        network: nid,
        nonce,
        height,
        tip,
        listen: advertised_listen(&inner.cfg, &addr, inbound, proxied),
        relay_txs: true,
    };
    let result = async {
        writer
            .send(&Message::Version(ours).encode())
            .await
            .map_err(|e| e.to_string())?;
        let theirs = match recv_msg(&mut reader, HANDSHAKE_TIMEOUT).await? {
            Message::Version(v) => v,
            other => return Err(format!("expected version, got {}", other.kind())),
        };
        if theirs.protocol < MIN_PROTOCOL_VERSION {
            return Err(format!("protocol {} too old", theirs.protocol));
        }
        if theirs.network != nid {
            return Err("wrong network".into());
        }
        if inner.state().local_nonces.contains(&theirs.nonce) {
            return Err("connected to self".into());
        }
        writer
            .send(&Message::Verack.encode())
            .await
            .map_err(|e| e.to_string())?;
        // A later protocol version may send messages of types we do not
        // know before its `Verack` (feature negotiation): skipped.
        let mut skipped = 0;
        loop {
            let frame = tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.recv())
                .await
                .map_err(|_| "timeout".to_string())?
                .map_err(|e| e.to_string())?;
            if frame.first().is_some_and(|&t| !is_known_type(t))
                && skipped < HANDSHAKE_UNKNOWN_FRAMES
            {
                skipped += 1;
                continue;
            }
            return match Message::decode(&frame).map_err(|e| format!("decode: {e:?}"))? {
                Message::Verack => Ok(theirs),
                other => Err(format!("expected verack, got {}", other.kind())),
            };
        }
    }
    .await;
    inner.state().local_nonces.remove(&nonce);
    let theirs = match result {
        Ok(v) => v,
        Err(e) => {
            log::debug!("{addr}: handshake failed: {e}");
            return;
        }
    };

    // Register.
    let (tx_out, rx_out) = mpsc::channel::<Message>(OUTBOX);
    let (tx_bulk, rx_bulk) = mpsc::channel::<Message>(BULK_OUTBOX);
    let kill = Arc::new(Notify::new());
    let id = inner.next_id.fetch_add(1, Ordering::Relaxed);
    {
        let mut st = inner.state();
        if let Some(slot) = slot.as_mut() {
            slot.release(&mut st);
        }
        // Re-check the inbound limits at registration, under the same lock
        // as the insertion (the accept-time check counted this connection
        // as handshaking), and a ban that came in during the handshake.
        if inbound {
            let over = addr.ip().is_some_and(|ip| {
                st.bans.is_banned(&ip, unix_now())
                    || (!inner.cfg.allow_private && same_ip_count(&st, ip) >= inner.cfg.max_per_ip)
            }) || inbound_count(&st) >= inner.cfg.max_inbound;
            if over {
                log::debug!("{addr}: inbound limit reached at registration");
                return;
            }
        }
        if !inbound {
            st.addrman.mark_good(&addr, unix_now());
        }
        if let Some(listen) = &theirs.listen {
            if inbound && (listen.is_routable() || inner.cfg.allow_private) {
                let src = addr.clone();
                let State { addrman, rng, .. } = &mut *st;
                addrman.add(listen.clone(), &src, rng);
            }
        }
        let now = Instant::now();
        st.peers.insert(
            id,
            Peer {
                addr: addr.clone(),
                inbound,
                proxied,
                protocol: theirs.protocol,
                out: tx_out,
                bulk: tx_bulk,
                kill: kill.clone(),
                relay_txs: theirs.relay_txs,
                height: theirs.height,
                score: 0,
                limits: inner.cfg.peer_limits.clone(),
                answered_getaddr: false,
                received_addr_batch: false,
                inv_queue: Vec::new(),
                next_inv: now,
                announced_to: HashSet::new(),
                known_txs: HashSet::new(),
                ping: None,
                last_ping: now,
                last_recv: now,
                blocks_in_flight: 0,
                bytes_in_flight: 0,
                headers_requested: None,
                headers_grace: None,
                headers_busy: false,
                headers_pending: false,
                warned_upgrade: false,
            },
        );
    }
    log::info!(
        "connected {} peer {addr} (height {})",
        if inbound { "inbound" } else { "outbound" },
        theirs.height
    );
    let writer_task = tokio::spawn(write_loop(writer, rx_out, rx_bulk));
    if !inbound {
        inner.send_now(id, Message::GetAddr);
    }
    if theirs.height > height {
        inner.request_headers(id).await;
    }

    // Read loop.
    loop {
        tokio::select! {
            _ = kill.notified() => break,
            frame = tokio::time::timeout(IDLE_TIMEOUT, reader.recv()) => {
                let frame = match frame {
                    Err(_) => { log::debug!("{addr}: idle timeout"); break; }
                    Ok(Err(TransportError::Io(_))) => break,
                    Ok(Err(e)) => { inner.misbehave(id, score::PROTOCOL, &format!("transport: {e}")); break; }
                    Ok(Ok(f)) => f,
                };
                // Rate limits. Every message counts against the message budget.
                let over = {
                    let mut st = inner.state();
                    let now = Instant::now();
                    match st.peers.get_mut(&id) {
                        Some(p) => {
                            p.last_recv = now;
                            !p.limits.messages.take(1.0, now)
                        }
                        None => break,
                    }
                };
                if over {
                    inner.misbehave(id, score::RATE, "rate limit");
                    continue;
                }
                // A message type of a later protocol version (P0-8): ignored,
                // not penalized, but charged against the byte budget like
                // any unsolicited message (and the message budget above).
                if frame.first().is_some_and(|&t| !is_known_type(t)) {
                    let over = {
                        let mut st = inner.state();
                        let now = Instant::now();
                        match st.peers.get_mut(&id) {
                            Some(p) => !p.limits.bytes.take(frame.len() as f64, now),
                            None => break,
                        }
                    };
                    if over {
                        inner.misbehave(id, score::RATE, "byte rate limit");
                    } else {
                        log::debug!("{addr}: ignored a message of unknown type {}", frame[0]);
                    }
                    continue;
                }
                let msg = match Message::decode(&frame) {
                    Ok(m) => m,
                    Err(e) => { inner.misbehave(id, score::PROTOCOL, &format!("malformed message: {e:?}")); break; }
                };
                // The byte budget limits what a peer sends on its own initiative.
                // Answers to our own requests are exempt: a block we requested
                // (bounded by our request window, BLOCKS_IN_FLIGHT blocks of at
                // most MAX_BLOCK_BYTES) and the headers we asked for (one
                // outstanding request, at most MAX_HEADERS headers). Charging
                // them would drop the data we asked for during a sync.
                let requested = requested_by_us(&inner, id, &msg);
                let over = !requested && {
                    let mut st = inner.state();
                    let now = Instant::now();
                    match st.peers.get_mut(&id) {
                        Some(p) => !p.limits.bytes.take(frame.len() as f64, now),
                        None => break,
                    }
                };
                if over {
                    inner.misbehave(id, score::RATE, "byte rate limit");
                    continue;
                }
                handle(&inner, id, msg).await;
            }
        }
    }

    // Cleanup.
    writer_task.abort();
    let mut st = inner.state();
    if let Some(p) = st.peers.remove(&id) {
        log::info!("disconnected peer {}", p.addr);
    }
    st.dandelion.peer_disconnected(id);
    st.block_requests.retain(|_, (p, _)| *p != id);
    // Transaction requests this peer owned move to the next announcer now,
    // not after TX_TIMEOUT; announcer queues it leaves empty are dropped.
    let owned: Vec<Hash> = st
        .tx_requests
        .iter()
        .filter(|(_, (p, _))| *p == id)
        .map(|(h, _)| *h)
        .collect();
    let now = Instant::now();
    for h in owned {
        retry_tx(&inner, &mut st, h, id, now);
    }
    st.tx_announcers.retain(|_, q| {
        q.retain(|p| *p != id);
        !q.is_empty()
    });
}

/// Sends a peer's queued messages: control messages (pongs, headers, relay)
/// strictly before queued `Block` frames, so a pong never waits behind a
/// batch of blocks (R8-11). A frame already being written is not interrupted.
async fn write_loop<W: AsyncWrite + Unpin>(
    mut writer: FrameWriter<W>,
    mut control: mpsc::Receiver<Message>,
    mut bulk: mpsc::Receiver<Message>,
) {
    loop {
        let msg = tokio::select! {
            biased;
            m = control.recv() => m,
            m = bulk.recv() => m,
        };
        let Some(msg) = msg else { break };
        if writer.send(&msg.encode()).await.is_err() {
            break;
        }
    }
}

// ---------------------------------------------------------------- handlers

/// Whether `msg` answers a request we sent `peer` and are still waiting for:
/// a block we requested (only its header, the first `HEADER_SIZE` bytes, is
/// read), or headers while a `GetHeaders` is outstanding.
fn requested_by_us(inner: &Inner, peer: PeerId, msg: &Message) -> bool {
    let bytes = match msg {
        Message::Block(bytes) => bytes,
        Message::Headers(h) => {
            let now = Instant::now();
            return inner.state().peers.get(&peer).is_some_and(|p| {
                p.headers_requested.is_some() || (h.len() > 1 && in_grace(p.headers_grace, now))
            });
        }
        _ => return false,
    };
    let Some(header) = bytes
        .get(..blacksilk_consensus::HEADER_SIZE)
        .and_then(BlockHeader::from_bytes)
    else {
        return false;
    };
    let id = header.id(inner.cfg.network_id);
    let st = inner.state();
    st.block_requests
        .get(&id)
        .or_else(|| st.late_blocks.get(&id))
        .is_some_and(|(p, _)| *p == peer)
}

async fn handle(inner: &Arc<Inner>, peer: PeerId, msg: Message) {
    match msg {
        Message::Version(_) | Message::Verack => {
            inner.misbehave(peer, score::PROTOCOL, "duplicate version/verack");
        }
        Message::Ping(n) => inner.send_now(peer, Message::Pong(n)),
        Message::Pong(n) => {
            let ok = {
                let mut st = inner.state();
                match st.peers.get_mut(&peer) {
                    Some(p) if p.ping.map(|(x, _)| x) == Some(n) => {
                        p.ping = None;
                        true
                    }
                    _ => false,
                }
            };
            if !ok {
                inner.misbehave(peer, score::UNSOLICITED, "unexpected pong");
            }
        }
        Message::GetAddr => on_get_addr(inner, peer),
        Message::Addr(addrs) => on_addr(inner, peer, addrs),
        Message::GetHeaders { locator, stop } => {
            let headers = inner
                .with_chain(move |c| c.headers_after(&locator, &stop, MAX_HEADERS as usize))
                .await;
            inner.send_now(peer, Message::Headers(headers));
        }
        Message::Headers(headers) => on_headers(inner, peer, headers).await,
        Message::GetBlocks(ids) => on_get_blocks(inner, peer, ids).await,
        Message::Block(bytes) => on_block(inner, peer, bytes),
        Message::NotFound(ids) => {
            let mut st = inner.state();
            let now = Instant::now();
            for id in ids {
                if st.block_requests.get(&id).is_some_and(|(p, _)| *p == peer) {
                    st.block_requests.remove(&id);
                    release_block_slot(&mut st, peer);
                }
                if st.tx_requests.get(&id).is_some_and(|(p, _)| *p == peer) {
                    retry_tx(inner, &mut st, id, peer, now);
                }
            }
        }
        Message::InvTx(ids) => on_inv_tx(inner, peer, ids).await,
        Message::GetTx(ids) => on_get_tx(inner, peer, ids).await,
        Message::Tx(bytes) => on_tx(inner, peer, bytes).await,
        Message::StemTx(bytes) => on_stem_tx(inner, peer, bytes).await,
    }
}

fn on_get_addr(inner: &Arc<Inner>, peer: PeerId) {
    let mut st = inner.state();
    let Some(p) = st.peers.get_mut(&peer) else {
        return;
    };
    if p.answered_getaddr {
        drop(st);
        inner.misbehave(peer, score::UNSOLICITED, "repeated getaddr");
        return;
    }
    p.answered_getaddr = true;
    let now = unix_now();
    let allow_private = inner.cfg.allow_private;
    let State {
        addrman, rng, bans, ..
    } = &mut *st;
    let sample: Vec<NetAddr> = addrman
        .sample(1000, rng)
        .into_iter()
        .filter(|a| a.is_routable() || allow_private)
        .filter(|a| a.ip().is_none_or(|ip| !bans.is_banned(&ip, now)))
        .collect();
    inner.send(&mut st, peer, Message::Addr(sample));
}

fn on_addr(inner: &Arc<Inner>, peer: PeerId, addrs: Vec<NetAddr>) {
    let mut st = inner.state();
    let Some(p) = st.peers.get_mut(&peer) else {
        return;
    };
    if addrs.len() > 10 {
        // One large batch (the answer to our GetAddr) per connection.
        if p.received_addr_batch {
            drop(st);
            inner.misbehave(peer, score::UNSOLICITED, "unsolicited address batch");
            return;
        }
        p.received_addr_batch = true;
    }
    let source = p.addr.clone();
    let allow_private = inner.cfg.allow_private;
    let mut fresh = Vec::new();
    {
        let State { addrman, rng, .. } = &mut *st;
        for a in addrs {
            if (a.is_routable() || allow_private) && addrman.add(a.clone(), &source, rng) {
                fresh.push(a);
            }
        }
    }
    // Relay small announcements of new addresses to two random peers.
    if !fresh.is_empty() && fresh.len() <= 10 {
        let mut others: Vec<PeerId> = st.peers.keys().copied().filter(|&p| p != peer).collect();
        for _ in 0..2.min(others.len()) {
            let i = (st.rng.next_u64() % others.len() as u64) as usize;
            let target = others.swap_remove(i);
            inner.send(&mut st, target, Message::Addr(fresh.clone()));
        }
    }
}

fn in_grace(grace: Option<Instant>, now: Instant) -> bool {
    grace.is_some_and(|t| now.duration_since(t) <= HEADERS_TIMEOUT)
}

/// Receives a `Headers` message on the peer's read loop. Only cheap checks run
/// here; the batch is verified by the header worker, so the read loop keeps
/// answering pings however long the proof of work takes (docs/p2p.md §6).
async fn on_headers(inner: &Arc<Inner>, peer: PeerId, headers: Vec<BlockHeader>) {
    let nid = inner.cfg.network_id;
    // Only needed for an empty reply; read before the state lock (the two
    // locks are never held together).
    let ours = if headers.is_empty() {
        Some(inner.with_chain(|c| c.header_height()).await)
    } else {
        None
    };
    let penalty = {
        let mut st = inner.state();
        let room = st
            .peers
            .get(&peer)
            .is_some_and(|p| inner.header_queue_room(&st, &p.addr));
        let Some(p) = st.peers.get_mut(&peer) else {
            return;
        };
        let now = Instant::now();
        let solicited = if let Some(t) = p.headers_requested.take() {
            // One header may be a tip announcement that crossed our request:
            // the real (multi-header) reply may still come, once.
            p.headers_grace = (headers.len() == 1).then_some(t);
            true
        } else if headers.len() > 1 && in_grace(p.headers_grace, now) {
            p.headers_grace = None;
            true
        } else {
            false
        };
        if let Some(ours) = ours {
            // An empty answer: the peer has nothing after our locator. Stop
            // asking it every tick until it announces something new.
            if solicited {
                p.height = p.height.min(ours);
            }
            return;
        }
        if !solicited && headers.len() > 1 {
            // Unrequested headers are tip announcements: one header. A longer
            // batch would make us verify work we never asked for.
            Some((score::UNSOLICITED, "unrequested header batch"))
        } else if headers
            .windows(2)
            .any(|w| w[1].prev_id != w[0].id(nid) || w[1].height != w[0].height + 1)
        {
            Some((score::UNCONNECTED_HEADERS, "headers are not a chain"))
        } else if p.headers_busy || !room {
            // Still verifying this peer's previous batch, or the queue is
            // full (for this origin or in total): ask again afterwards.
            p.headers_pending = true;
            None
        } else {
            p.headers_busy = true;
            let batch = HeaderBatch {
                peer,
                addr: p.addr.clone(),
                proxied: p.proxied,
                solicited,
                headers,
            };
            let key = queue_key(&batch.addr);
            if inner.header_queue.send(batch).is_err() {
                p.headers_busy = false;
                log::error!("header worker stopped: header batch dropped");
            } else {
                st.header_queue_len += 1;
                *st.header_queue_origin.entry(key).or_default() += 1;
            }
            None
        }
    };
    if let Some((points, reason)) = penalty {
        inner.misbehave(peer, points, reason);
    }
}

/// Outcome of verifying one header batch.
enum HeaderOutcome {
    /// Every header is stored (new or already known). `last` is the height of
    /// the last one, `last_id` its id; `advanced`: the batch added headers, or
    /// ends on a stored branch that is not our best chain (a fork being
    /// fetched), so asking the peer for more is useful.
    Accepted {
        last: u64,
        last_id: Hash,
        advanced: bool,
    },
    /// The batch's cumulative work would not exceed our best header chain's
    /// (and it cannot be the start of a heavier branch, `low_work`): dropped
    /// without proof of work, without penalty and without re-requesting.
    LowWork,
    /// The first header does not connect to anything we know.
    Unconnected,
    /// A header failed; the ones before it are stored, unless the failure is
    /// one the sender is penalized for (then nothing is hashed or stored).
    Failed(HeaderError),
    /// The sender left or was banned before its batch was verified; only the
    /// cheap pre-check ran (a pre-check violation is still a `Failed`).
    Abandoned,
}

/// Header errors the sender is penalized for (see `on_header_error`).
fn penalized(e: &HeaderError) -> bool {
    !matches!(
        e,
        HeaderError::Duplicate
            | HeaderError::TimestampTooFarInFuture { .. }
            | HeaderError::InvalidParent
            | HeaderError::UnknownParent
            | HeaderError::UnknownUpgrade { .. }
    )
}

/// Verifies header batches one at a time (docs/p2p.md §6):
/// 1. every rule except proof of work, for the whole batch, before any RandomX
///    hash (`ChainManager::precheck_headers`); a violation the sender is
///    penalized for rejects the batch without any hash;
/// 2. headers already stored are skipped, and a batch whose work cannot beat
///    our best header chain is dropped (`low_work`);
/// 3. proof of work in chunks of `pow_threads` headers, each chunk accepted
///    before the next is hashed, so a batch that fails costs at most one
///    chunk of hashes beyond its last valid header.
///
/// One worker for all peers: batches from several peers covering the same
/// headers are hashed once (the second finds them stored). The queue is
/// bounded per origin and in total (`Inner::header_queue_room`); batches of
/// senders that left or were banned are only pre-checked.
async fn header_worker(inner: Arc<Inner>, mut rx: mpsc::UnboundedReceiver<HeaderBatch>) {
    while let Some(mut batch) = rx.recv().await {
        let peer = batch.peer;
        let headers = std::mem::take(&mut batch.headers);
        let full = headers.len() as u64 == MAX_HEADERS;
        let count = headers.len();
        let last_height = headers.last().map_or(0, |h| h.height);
        let inner2 = inner.clone();
        let addr = batch.addr.clone();
        // Our header height after the batch is read on the same blocking
        // thread, so the peer's claimed height is corrected below under the
        // same state lock that ends `headers_busy`: the maintenance loop
        // never sees the peer idle with its stale (higher) height, which
        // would ask it again (R8-15 request loops).
        let result = tokio::task::spawn_blocking(move || {
            let outcome = verify_headers(&inner2, peer, &addr, &headers);
            let ours = inner2.chain().header_height();
            (outcome, ours)
        })
        .await;
        let (outcome, ours) = match result {
            Ok((outcome, ours)) => (Ok(outcome), ours),
            Err(e) => (Err(e), 0),
        };
        let pending = {
            let mut st = inner.state();
            st.header_queue_len = st.header_queue_len.saturating_sub(1);
            let key = queue_key(&batch.addr);
            if let Some(n) = st.header_queue_origin.get_mut(&key) {
                *n -= 1;
                if *n == 0 {
                    st.header_queue_origin.remove(&key);
                }
            }
            match st.peers.get_mut(&peer) {
                Some(p) => {
                    p.headers_busy = false;
                    match &outcome {
                        Ok(HeaderOutcome::Accepted { last, advanced, .. }) => {
                            p.height = p.height.max(*last);
                            if !advanced && batch.solicited {
                                // A solicited reply that taught us nothing:
                                // do not ask this peer again every tick.
                                p.height = p.height.min(ours.max(*last));
                            }
                        }
                        Ok(HeaderOutcome::LowWork) if batch.solicited => {
                            p.height = p.height.min(ours);
                        }
                        // After relaying headers of a block whose body is
                        // invalid, the peer is not asked again until it
                        // announces a new tip (`on_header_error`).
                        Ok(HeaderOutcome::Failed(HeaderError::InvalidParent)) => {
                            p.height = p.height.min(ours);
                        }
                        _ => {}
                    }
                    std::mem::take(&mut p.headers_pending)
                }
                None => false,
            }
        };
        match outcome {
            Ok(HeaderOutcome::Accepted {
                last_id, advanced, ..
            }) => {
                if full && advanced {
                    inner.request_headers_after(peer, Some(last_id)).await;
                } else if pending {
                    inner.request_headers(peer).await;
                }
            }
            Ok(HeaderOutcome::LowWork) => {
                log::debug!(
                    "peer {peer}: {count} headers up to height {last_height} do not beat our best chain; dropped"
                );
                // Not re-requested because of this batch. Headers the peer
                // sent meanwhile (e.g. the child that makes an equal-work
                // rival heavier) are asked for again.
                if pending {
                    inner.request_headers(peer).await;
                }
            }
            Ok(HeaderOutcome::Unconnected) => {
                // A gap or a deeper fork: fetch from our locator.
                if count > 1 {
                    inner.misbehave_departed(
                        &batch,
                        score::UNCONNECTED_HEADERS,
                        "headers do not connect",
                    );
                }
                inner.request_headers(peer).await;
            }
            Ok(HeaderOutcome::Failed(e)) => {
                on_header_error(&inner, &batch, e, last_height, pending).await
            }
            Ok(HeaderOutcome::Abandoned) => {}
            // `verify_headers` takes the chain lock: a panic there poisoned it.
            Err(e) if e.is_panic() => fatal(&format!("header task failed: {e}")),
            Err(_) => return, // the runtime is shutting down
        }
        schedule_downloads(&inner).await;
    }
}

/// Whether the sender of a queued batch is still connected and not banned.
fn sender_live(inner: &Inner, peer: PeerId, addr: &NetAddr) -> bool {
    let st = inner.state();
    st.peers.contains_key(&peer)
        && addr
            .ip()
            .is_none_or(|ip| !st.bans.is_banned(&ip, unix_now()))
}

/// Blocks of main-chain work below our best that a competing branch may lack
/// and still be verified and stored (R1-C1; Bitcoin Core's anti-DoS work
/// threshold uses 144 blocks as well).
const ANTI_DOS_BLOCKS: u64 = 144;

/// Claimed cumulative work a branch must reach to be hashed and stored:
/// `best_work - work(last ANTI_DOS_BLOCKS main blocks)`, i.e. the work of our
/// best chain at `tip - ANTI_DOS_BLOCKS`. There is no hard-coded minimum
/// chain work (docs/p2p.md §12).
fn anti_dos_threshold(hc: &HeaderChain) -> u128 {
    let base = hc.height().saturating_sub(ANTI_DOS_BLOCKS);
    hc.main_id_at(base).and_then(|id| hc.work(&id)).unwrap_or(0)
}

/// Whether headers `fresh` (linked, not stored, every rule but PoW checked,
/// the first one's parent stored) are worth their proof of work: RandomX
/// hashes are spent only on headers that can make a chain competitive with
/// our best one (docs/p2p.md §6). The difficulties are the required ones (the
/// pre-check passed), so the sums below are the work the headers claim.
///
/// - The batch's claimed tip work reaches `anti_dos_threshold` (our best
///   work minus that of our last 144 blocks): verify. This covers every
///   extension of our best chain and near-tip competing branches.
/// - Otherwise, if the message was not a full batch (`MAX_HEADERS`), the
///   peer's branch ends here, far below our work: dropped.
/// - A full batch may be the start of a longer, heavier branch (a fork deeper
///   than one batch). It is verified only if its work per height is at least
///   half of our best chain's over the same heights (our tip's difficulty for
///   heights above our tip). Cheap branches (difficulty driven down with
///   spread-out timestamps) fail this; an honest competing branch, mined at
///   comparable difficulty, passes.
fn worth_verifying(hc: &HeaderChain, fresh: &[BlockHeader], full: bool) -> bool {
    let Some(first) = fresh.first() else {
        return true;
    };
    let Some(parent_work) = hc.work(&first.prev_id) else {
        return true; // not reached: the parent is stored
    };
    let batch: u128 = fresh.iter().map(|h| h.difficulty as u128).sum();
    if parent_work + batch >= anti_dos_threshold(hc) {
        return true;
    }
    if !full {
        return false;
    }
    let last = first.height + fresh.len() as u64 - 1;
    let tip = hc.height();
    let tip_difficulty = hc.tip().difficulty as u128;
    let ours = if first.height > tip {
        tip_difficulty * fresh.len() as u128
    } else {
        let top = last.min(tip);
        let work_at = |h: u64| hc.main_id_at(h).and_then(|id| hc.work(&id)).unwrap_or(0);
        work_at(top).saturating_sub(work_at(first.height - 1))
            + tip_difficulty * (last - top) as u128
    };
    batch.saturating_mul(2) >= ours
}

/// Pre-check, then chunked proof of work and acceptance. Runs on a blocking
/// thread; the chain lock is held only for the cheap steps, never while
/// hashing.
fn verify_headers(
    inner: &Inner,
    peer: PeerId,
    addr: &NetAddr,
    headers: &[BlockHeader],
) -> HeaderOutcome {
    let now = unix_now();
    let full = headers.len() as u64 == MAX_HEADERS;
    let live = sender_live(inner, peer, addr);
    if !live
        && addr
            .ip()
            .is_some_and(|ip| inner.state().bans.is_banned(&ip, now))
    {
        return HeaderOutcome::Abandoned;
    }
    let nid = inner.cfg.network_id;
    let (checked, fresh_range, worth) = {
        let c = inner.chain();
        if c.header(&headers[0].prev_id).is_none() {
            return HeaderOutcome::Unconnected;
        }
        let checked = c.precheck_headers(headers, now);
        let good_end = match &checked {
            Ok(()) => headers.len(),
            Err((i, _)) => *i,
        };
        // Headers we already have (a prefix: a stored header cannot follow
        // an unstored one) cost nothing more.
        let start = headers[..good_end]
            .iter()
            .position(|h| c.header(&h.id(nid)).is_none())
            .unwrap_or(good_end);
        let worth = worth_verifying(c.headers(), &headers[start..good_end], full);
        (checked, start..good_end, worth)
    };
    let precheck_error = match checked {
        // A violation the sender is banned for: no hash for its batch.
        Err((_, e)) if penalized(&e) => return HeaderOutcome::Failed(e),
        Err((_, e)) => Some(e),
        Ok(()) => None,
    };
    if !live {
        return HeaderOutcome::Abandoned;
    }
    if !worth {
        return HeaderOutcome::LowWork;
    }
    let fresh = &headers[fresh_range];
    let chunk = inner.cfg.pow_threads.max(1);
    let mut new = 0;
    for (k, part) in fresh.chunks(chunk).enumerate() {
        if k > 0 && !sender_live(inner, peer, addr) {
            return HeaderOutcome::Abandoned;
        }
        let jobs = inner.chain().pow_jobs(part);
        let Some((pow, jobs)) = jobs else {
            return HeaderOutcome::Unconnected;
        };
        pow.compute_parallel(&jobs, chunk);
        match inner.chain().accept_headers(part, now) {
            Ok(n) => new += n,
            Err((_, e)) => return HeaderOutcome::Failed(e),
        }
    }
    if let Some(e) = precheck_error {
        return HeaderOutcome::Failed(e);
    }
    let last = headers.last().expect("a batch is not empty");
    let last_id = last.id(nid);
    let on_main = inner.chain().headers().is_on_main(&last_id);
    HeaderOutcome::Accepted {
        last: last.height,
        last_id,
        advanced: new > 0 || !on_main,
    }
}

/// Penalties for a failed header batch. Only failures a peer can check itself
/// from the headers are penalized:
/// - `InvalidParent` means the header descends from a block whose *body* we
///   found invalid. A peer relaying headers cannot know that without the body
///   (it may not have downloaded it yet, or its sender withholds it), so it is
///   not penalized; we stop asking it for headers until it announces again.
/// - `Duplicate` and `TimestampTooFarInFuture` are not permanent.
/// - `UnknownUpgrade`: the header's version is above every version this
///   node's schedule knows, so the peer probably runs a newer release and may
///   be right. It is not penalized; the operator is warned once per peer
///   (docs/consensus.md §11, docs/p2p.md §6).
/// - Every other failure is a header that breaks the rules: the peer relayed
///   it without checking, and is penalized.
///
/// Headers that arrived from the peer meanwhile (`pending`) are asked for
/// again whenever the peer is not penalized.
async fn on_header_error(
    inner: &Arc<Inner>,
    batch: &HeaderBatch,
    e: HeaderError,
    last_height: u64,
    pending: bool,
) {
    let peer = batch.peer;
    match e {
        HeaderError::Duplicate | HeaderError::TimestampTooFarInFuture { .. } => {
            if pending {
                inner.request_headers(peer).await;
            }
        }
        HeaderError::UnknownParent => inner.request_headers(peer).await,
        HeaderError::UnknownUpgrade { version } => inner.warn_unknown_upgrade(peer, version),
        HeaderError::InvalidParent => {
            log::info!(
                "peer {peer} relays headers (up to height {last_height}) descending from a block with an invalid body"
            );
            // Its claimed height was lowered to ours by the header worker.
            if pending {
                inner.request_headers(peer).await;
            }
        }

        e => inner.misbehave_departed(
            batch,
            score::INVALID_HEADER,
            &format!("invalid header: {e}"),
        ),
    }
}

async fn on_get_blocks(inner: &Arc<Inner>, peer: PeerId, ids: Vec<Hash>) {
    // Copied and encoded under the lock on a blocking thread; queued after.
    let (found, missing): (Vec<Vec<u8>>, Vec<Hash>) = inner
        .with_chain(move |c| {
            let mut found = Vec::new();
            let mut missing = Vec::new();
            for id in ids {
                match c.block(&id) {
                    Some(b) if found.len() < SERVE_BLOCKS_PER_REQUEST => found.push(b.encode()),
                    _ => missing.push(id),
                }
            }
            (found, missing)
        })
        .await;
    let mut st = inner.state();
    for b in found {
        inner.send(&mut st, peer, Message::Block(b));
    }
    if !missing.is_empty() {
        inner.send(&mut st, peer, Message::NotFound(missing));
    }
}

/// Frees one place in `peer`'s block request window (`BLOCKS_IN_FLIGHT`,
/// `BLOCK_WINDOW_BYTES`): the request was answered and processed, answered
/// `NotFound`, or timed out.
fn release_block_slot(st: &mut State, peer: PeerId) {
    if let Some(p) = st.peers.get_mut(&peer) {
        p.blocks_in_flight = p.blocks_in_flight.saturating_sub(1);
        p.bytes_in_flight = p.bytes_in_flight.saturating_sub(MAX_BLOCK_BYTES);
    }
}

/// Receives a `Block` on the peer's read loop: decoded and matched against
/// our requests here, then handed to the block worker, so the read loop keeps
/// answering pings however long the block takes to connect (R8-1).
fn on_block(inner: &Arc<Inner>, peer: PeerId, bytes: Vec<u8>) {
    let block = match Block::decode(&bytes) {
        Ok(b) => b,
        Err(e) => {
            inner.misbehave(
                peer,
                score::INVALID_BLOCK,
                &format!("block does not decode: {e:?}"),
            );
            return;
        }
    };
    let id = block.id(inner.cfg.network_id);
    let job = {
        let mut st = inner.state();
        let requested = st.block_requests.get(&id).is_some_and(|(p, _)| *p == peer);
        if requested {
            // Out of the timeout sweep; its window place is freed once the
            // block worker has processed it.
            st.block_requests.remove(&id);
        }
        let late = st.late_blocks.get(&id).is_some_and(|(p, _)| *p == peer);
        if late {
            st.late_blocks.remove(&id);
        }
        let unrequested = !requested && !late;
        if unrequested && st.unrequested_queued >= UNREQUESTED_QUEUE {
            None
        } else {
            if unrequested {
                st.unrequested_queued += 1;
            }
            st.blocks_queued.insert(id);
            Some(BlockJob {
                peer,
                block,
                requested,
                late,
            })
        }
    };
    let solicited = job.as_ref().is_some_and(|j| j.requested || j.late);
    if !solicited {
        inner.misbehave(peer, score::UNSOLICITED, "unrequested block");
    }
    if let Some(job) = job {
        if inner.block_queue.send(job).is_err() {
            log::error!("block worker stopped: block dropped");
        }
    }
}

/// Validates and connects received blocks, one at a time, in arrival order
/// (docs/p2p.md §6). Each block is connected through the bounded API
/// (`submit_block_in_steps`): at most `SYNC_STEP_BLOCKS` block validations
/// per chain-lock hold, so the gap-filling block of a long download does not
/// hold the lock while hundreds of waiting descendants connect.
async fn block_worker(inner: Arc<Inner>, mut rx: mpsc::UnboundedReceiver<BlockJob>) {
    while let Some(job) = rx.recv().await {
        let BlockJob {
            peer,
            block,
            requested,
            late,
        } = job;
        let unrequested = !requested && !late;
        let id = block.id(inner.cfg.network_id);
        let inner2 = inner.clone();
        let result = tokio::task::spawn_blocking(move || {
            // Only a block whose header we already accepted (so it passed
            // the header gate, `worth_verifying`) is worth storing, e.g. a
            // requested block arriving after its timeout. Any other
            // unrequested body, for instance of a free low-work branch, is
            // dropped before it is hashed or written (R1-C1).
            if unrequested && inner2.chain().header(&id).is_none() {
                return None;
            }
            Some(submit_block_in_steps(
                || inner2.chain(),
                block,
                unix_now(),
                SYNC_STEP_BLOCKS,
            ))
        })
        .await;
        {
            let mut st = inner.state();
            if requested {
                release_block_slot(&mut st, peer);
            }
            if unrequested {
                st.unrequested_queued = st.unrequested_queued.saturating_sub(1);
            }
            st.blocks_queued.remove(&id);
        }
        match result {
            Ok(None) | Ok(Some(Ok(_))) | Ok(Some(Err(SubmitError::Duplicate))) => {}
            Ok(Some(Err(SubmitError::BodyMismatch))) => {
                inner.misbehave(peer, score::INVALID_BLOCK, "body does not match header")
            }
            Ok(Some(Err(SubmitError::Body(e)))) => {
                inner.misbehave(peer, score::INVALID_BLOCK, &format!("invalid block: {e:?}"))
            }
            Ok(Some(Err(SubmitError::Header(e)))) => match e {
                // `InvalidParent`: the parent's body was found invalid,
                // possibly after we requested this block (a race), so it is
                // not the sender's fault; an unrequested block was already
                // charged on arrival.
                HeaderError::Duplicate
                | HeaderError::TimestampTooFarInFuture { .. }
                | HeaderError::InvalidParent => {}
                HeaderError::UnknownParent => inner.request_headers(peer).await,
                HeaderError::UnknownUpgrade { version } => {
                    inner.warn_unknown_upgrade(peer, version)
                }
                e => inner.misbehave(
                    peer,
                    score::INVALID_HEADER,
                    &format!("invalid block header: {e}"),
                ),
            },
            Ok(Some(Err(SubmitError::Store(e)))) => log::error!("block store: {e}"),
            // The task holds the chain lock: a panic there poisoned it.
            Err(e) if e.is_panic() => fatal(&format!("block task failed: {e}")),
            Err(_) => return, // the runtime is shutting down
        }
        schedule_downloads(&inner).await;
    }
}

/// Requests missing best-chain bodies from peers that have them (docs/p2p.md
/// §6), within each peer's window: `BLOCKS_IN_FLIGHT` blocks and
/// `BLOCK_WINDOW_BYTES` (each request charged `MAX_BLOCK_BYTES`), at least
/// one block.
async fn schedule_downloads(inner: &Arc<Inner>) {
    let missing = inner.with_chain(|c| c.missing_bodies(256)).await;
    if missing.is_empty() {
        return;
    }
    let mut st = inner.state();
    let now = Instant::now();
    let mut batches: HashMap<PeerId, Vec<Hash>> = HashMap::new();
    for (height, id) in missing {
        if st.block_requests.contains_key(&id) || st.blocks_queued.contains(&id) {
            continue;
        }

        let candidates: Vec<PeerId> = st
            .peers
            .iter()
            .filter(|(_, p)| p.height >= height && window_has_room(p))
            .map(|(id, _)| *id)
            .collect();
        if candidates.is_empty() {
            break;
        }
        let pick = candidates[(st.rng.next_u64() % candidates.len() as u64) as usize];
        let p = st.peers.get_mut(&pick).expect("candidate");
        p.blocks_in_flight += 1;
        p.bytes_in_flight += MAX_BLOCK_BYTES;
        st.block_requests.insert(id, (pick, now));
        batches.entry(pick).or_default().push(id);
    }
    for (peer, ids) in batches {
        inner.send(&mut st, peer, Message::GetBlocks(ids));
    }
}

/// Whether another block may be requested from `p` (`schedule_downloads`).
fn window_has_room(p: &Peer) -> bool {
    p.blocks_in_flight == 0
        || (p.blocks_in_flight < BLOCKS_IN_FLIGHT
            && p.bytes_in_flight + MAX_BLOCK_BYTES <= BLOCK_WINDOW_BYTES)
}

async fn on_inv_tx(inner: &Arc<Inner>, peer: PeerId, ids: Vec<Hash>) {
    let (ids, known, tip): (Vec<Hash>, Vec<bool>, Hash) = inner
        .with_chain(move |c| {
            let known = ids.iter().map(|id| c.mempool().contains(id)).collect();
            (ids, known, c.tip_id())
        })
        .await;
    let mut request = Vec::new();
    {
        let mut st = inner.state();
        let now = Instant::now();
        let Some(p) = st.peers.get_mut(&peer) else {
            return;
        };
        if !p.limits.txs.take(ids.len() as f64 * 0.1, now) {
            drop(st);
            inner.misbehave(peer, score::RATE, "inv rate");
            return;
        }
        remember(&mut p.known_txs, ids.iter().copied());
        for (id, in_mempool) in ids.into_iter().zip(known) {
            if in_mempool || st.recent_rejects_set.contains(&id) || ctx_rejected(&st, &id, &tip) {
                continue;
            }
            // A transaction in our stempool is treated like an unknown one:
            // requested, never fluffed because of an announcement. Answering
            // differently would tell a spy what is in our stempool, and let
            // it end the stem at will (I3-1). If it is really in fluff, the
            // transaction arrives and is pooled, which ends the embargo
            // (`on_tx`).
            let q = st.tx_announcers.entry(id).or_default();
            if !q.contains(&peer) && q.len() < 8 {
                q.push_back(peer);
            }
            if let std::collections::hash_map::Entry::Vacant(e) = st.tx_requests.entry(id) {
                e.insert((peer, now));
                request.push(id);
            }
        }
        if !request.is_empty() {
            inner.send(&mut st, peer, Message::GetTx(request));
        }
    }
}

async fn on_get_tx(inner: &Arc<Inner>, peer: PeerId, ids: Vec<Hash>) {
    // Serve only what we announced to this peer and still have. Everything else
    // gets the same `NotFound` answer, so the reply reveals nothing about the
    // stempool or mempool, and an honest requester can move on immediately.
    let announced: Vec<(Hash, bool)> = {
        let st = inner.state();
        let Some(p) = st.peers.get(&peer) else { return };
        ids.into_iter()
            .map(|id| (id, p.announced_to.contains(&id)))
            .collect()
    };
    let (txs, missing) = inner
        .with_chain(move |c| {
            let mut txs = Vec::new();
            let mut missing = Vec::new();
            for (id, ok) in announced {
                match c.mempool().get(&id).filter(|_| ok) {
                    Some(t) => txs.push(t.encode()),
                    None => missing.push(id),
                }
            }
            (txs, missing)
        })
        .await;

    let mut st = inner.state();
    for t in txs {
        inner.send(&mut st, peer, Message::Tx(t));
    }
    if !missing.is_empty() {
        inner.send(&mut st, peer, Message::NotFound(missing));
    }
}

/// Drops a transaction request that `failed` could not answer and asks the next
/// announcer, if any.
fn retry_tx(inner: &Inner, st: &mut State, id: Hash, failed: PeerId, now: Instant) {
    st.tx_requests.remove(&id);
    let next = st.tx_announcers.get_mut(&id).and_then(|q| {
        q.retain(|x| *x != failed);
        q.front().copied()
    });
    match next {
        Some(n) => {
            st.tx_requests.insert(id, (n, now));
            inner.send(st, n, Message::GetTx(vec![id]));
        }
        None => {
            st.tx_announcers.remove(&id);
        }
    }
}

fn decode_tx(bytes: &[u8]) -> Option<Transaction> {
    match Transaction::decode(bytes) {
        Ok(Transaction::Coinbase(_)) | Err(_) => None,
        Ok(t) => Some(t),
    }
}

/// Stem-pool conflict keys: key images, and PX nullifiers.
fn stem_keys(tx: &Transaction) -> Vec<[u8; 32]> {
    let mut keys: Vec<[u8; 32]> = tx.key_images().iter().map(|k| *k.bytes()).collect();
    if let Transaction::Px(t) = tx {
        keys.extend(t.nullifiers.iter().map(blacksilk_tx::px::digest_bytes));
    }
    keys
}

fn is_px(tx: &Transaction) -> bool {
    matches!(tx, Transaction::Px(_) | Transaction::PxDeploy(_))
}

/// The ring indices of each v1 input (for `provably_invalid_signature`).
fn input_rings(tx: &Transaction) -> Vec<Vec<u64>> {
    let inputs: &[blacksilk_tx::types::Input] = match tx {
        Transaction::Coinbase(_) => &[],
        Transaction::Transfer(t) => &t.inputs,
        Transaction::Px(t) => &t.inputs,
        Transaction::PxDeploy(t) => &t.inputs,
    };
    inputs.iter().map(|i| i.ring.to_vec()).collect()
}

/// Whether `id` failed a contextual rule at our current tip `tip`.
fn ctx_rejected(st: &State, id: &Hash, tip: &Hash) -> bool {
    st.ctx_rejects_tip == *tip && st.ctx_rejects.contains(id)
}

/// Remembers that `id` failed a contextual rule at tip `tip`: the same bytes
/// are not verified again until the tip changes (the cache is emptied then).
fn ctx_reject(st: &mut State, id: Hash, tip: Hash) {
    if st.ctx_rejects_tip != tip || st.ctx_rejects.len() >= RECENT_REJECTS {
        st.ctx_rejects.clear();
        st.ctx_rejects_tip = tip;
    }
    st.ctx_rejects.insert(id);
}

/// Everything a relayed transaction goes through before its expensive checks
/// (ring signatures, range proofs, PX proof), in order of cost (docs/p2p.md
/// §10):
/// 1. a transaction already proven invalid is dropped (and a peer stemming it
///    again is penalized);
/// 2. the peer's signature budget is charged one token per v1 input (one
///    CLSAG verification each), and a PX or deploy transaction its PX share;
/// 3. a transaction already in the mempool, one that conflicts with a pooled
///    transaction (same key image, nullifier, contract id or output key; the
///    pool keeps the first seen, so it would be refused after verification),
///    or one that failed a contextual rule at the current tip, is dropped
///    unverified;
/// 4. cheap checks: PX structure and balance (stateless), then the contextual
///    rules an extension can change (key images, one-time keys, PX anchor,
///    nullifiers, registry, pool, contract id);
/// 5. only then the node-wide PX token: transactions that fail the cheap
///    checks (e.g. a random PX anchor) never consume it, so they cannot
///    starve honest PX relay.
///
/// `stem`: an unsolicited `StemTx` (rate excesses are penalized) rather than a
/// `Tx` we requested (never penalized for its rate: we asked for it; over a
/// limit it is dropped unverified). Returns whether to verify.
async fn admit_tx(
    inner: &Arc<Inner>,
    peer: PeerId,
    tx: &Transaction,
    id: Hash,
    stem: bool,
) -> bool {
    let now = Instant::now();
    let px = is_px(tx);
    let over = {
        let mut st = inner.state();
        if st.recent_rejects_set.contains(&id) {
            drop(st);
            if stem {
                inner.misbehave(peer, score::INVALID_TX, "known invalid transaction");
            }
            return false;
        }
        let cost = tx.key_images().len().max(1) as f64;
        let Some(p) = st.peers.get_mut(&peer) else {
            return false;
        };
        if !p.limits.inputs.take(cost, now) {
            Some("input rate")
        } else if px && !p.limits.px.take(1.0, now) {
            Some("PX stem rate")
        } else {
            None
        }
    };
    if let Some(reason) = over {
        log::debug!("transaction {} dropped: {reason}", short(&id));
        if stem {
            inner.misbehave(peer, score::RATE, reason);
        }
        return false;
    }
    let tx = Arc::new(tx.clone());
    let tx2 = tx.clone();
    let (tip, pooled, conflict) = inner
        .with_chain(move |c| {
            let pool = c.mempool();
            (c.tip_id(), pool.contains(&id), pool.conflicts(&tx2))
        })
        .await;
    // Already pooled (a replay): nothing to verify, no budget spent (SX2).
    // A conflict with a pooled transaction would be refused after
    // verification (first seen wins): dropped now, before the node-wide PX
    // token. Not penalized: the conflicting transaction may be an honest
    // double spend that lost a race.
    if pooled || ctx_rejected(&inner.state(), &id, &tip) {
        return false;
    }
    if conflict {
        log::debug!(
            "transaction {} conflicts with a pooled one; dropped",
            short(&id)
        );
        return false;
    }
    let cheap = inner
        .with_chain(move |c| {
            // The cheap stateless rules first, as in full validation: a
            // transaction that breaks one is penalized whatever its context.
            use blacksilk_tx::{px, validate};
            let rules = c.next_rules();
            let stateless = match &*tx {
                Transaction::Coinbase(_) => Err(blacksilk_tx::TxError::CoinbaseNotAllowed),
                Transaction::Transfer(t) => {
                    validate::check_structure(t, &rules).and_then(|_| validate::check_balance(t))
                }
                Transaction::Px(t) => {
                    px::check_px_structure(t).and_then(|_| px::check_px_balance(t))
                }
                Transaction::PxDeploy(t) => px::check_deploy_structure(t, &rules)
                    .and_then(|_| validate::check_balance(&t.as_transfer())),
            };
            stateless
                .and_then(|_| blacksilk_tx::validate::revalidate_after_extension(&tx, c.state()))
        })
        .await;
    if let Err(e) = cheap {
        if e.is_stateless() {
            Inner::reject_cache(&mut inner.state(), id);
            inner.misbehave(
                peer,
                score::INVALID_TX,
                &format!("invalid transaction: {e:?}"),
            );
        } else {
            log::debug!("transaction {} not valid here: {e:?}", short(&id));
            ctx_reject(&mut inner.state(), id, tip);
        }
        return false;
    }
    if px {
        let mut st = inner.state();
        if !st.px_global.take(1.0, now) {
            // Says nothing about this peer (others drain the bucket): never
            // penalized.
            st.px_global_drops += 1;
            log::debug!(
                "PX transaction {} dropped: node-wide relay limit",
                short(&id)
            );
            return false;
        }
    }
    true
}

/// Ring members this deep below our tip resolve to the same outputs on every
/// branch we could plausibly reorganize to, so a signature that fails over
/// them fails for every honest node too (docs/p2p.md §10). Far beyond the
/// reorganization depth that only warns (`DEEP_REORG_WARN_DEPTH` = 10): a
/// reorganization this deep would penalize honest relays, so the margin is
/// wide (the coinbase maturity). Spam over younger rings still pays the
/// per-peer input budget.
const SIGNATURE_BURIAL: u64 = 60;

/// Whether an `InvalidSignature` for an input with ring `ring` proves the
/// sender relayed an invalid transaction: every ring member is at least
/// `SIGNATURE_BURIAL` blocks below our tip.
fn provably_invalid_signature(c: &ChainManager, ring: Option<&Vec<u64>>) -> bool {
    use blacksilk_tx::validate::ChainView;
    let Some(ring) = ring else { return false };
    let tip = c.height();
    !ring.is_empty()
        && ring.iter().all(|&i| {
            c.state()
                .output(i)
                .is_some_and(|r| r.height + SIGNATURE_BURIAL <= tip)
        })
}

/// Whether the verification failure `e` of a transaction whose inputs have
/// rings `rings` proves that its relayer broke the rules: a stateless
/// failure, or a signature that fails over deeply buried ring members. Runs
/// under the chain lock, with the verification (same tip).
fn proven_invalid(c: &ChainManager, rings: &[Vec<u64>], e: &MempoolError) -> bool {
    match e {
        MempoolError::Invalid(e) => {
            // Near an activation, proofs and signatures made for the
            // neighbouring rule set fail honestly
            // (`validate::ACTIVATION_GRACE_BLOCKS`).
            let next = c.height() + 1;
            let near = blacksilk_tx::validate::near_activation(c.params(), next);
            e.is_stateless_at(c.params(), next)
                || match e {
                    blacksilk_tx::TxError::InvalidSignature { input } if !near => {
                        provably_invalid_signature(c, rings.get(*input))
                    }
                    _ => false,
                }
        }
        _ => false,
    }
}

/// A relayed transaction failed full verification at tip `tip`. Proven
/// failures (`proven_invalid`) are penalized and remembered for good. Other
/// (contextual) failures can be honest races: not penalized, and not
/// verified again at this tip.
fn on_invalid_tx(
    inner: &Arc<Inner>,
    peer: PeerId,
    id: Hash,
    tip: Hash,
    e: blacksilk_tx::TxError,
    proven: bool,
) {
    if proven {
        Inner::reject_cache(&mut inner.state(), id);
        inner.misbehave(
            peer,
            score::INVALID_TX,
            &format!("invalid transaction: {e:?}"),
        );
    } else {
        log::debug!("transaction {} not valid here: {e:?}", short(&id));
        ctx_reject(&mut inner.state(), id, tip);
    }
}

async fn on_tx(inner: &Arc<Inner>, peer: PeerId, bytes: Vec<u8>) {
    let Some(tx) = decode_tx(&bytes) else {
        inner.misbehave(peer, score::INVALID_TX, "transaction does not decode");
        return;
    };
    let id = tx.hash();
    let requested = {
        let mut st = inner.state();
        let r = st.tx_requests.get(&id).is_some_and(|(p, _)| *p == peer);
        if r {
            st.tx_requests.remove(&id);
            st.tx_announcers.remove(&id);
        }
        r
    };
    if !requested {
        inner.misbehave(peer, score::UNSOLICITED, "unrequested transaction");
        return;
    }
    if !admit_tx(inner, peer, &tx, id, false).await {
        return;
    }
    let rings = input_rings(&tx);
    let result = inner
        .with_chain(move |c| {
            let tip = c.tip_id();
            let r = c.submit_tx(tx);
            let proven = r.as_ref().is_err_and(|e| proven_invalid(c, &rings, e));
            (tip, r, proven)
        })
        .await;
    inner.state().tx_verifications += 1;
    match result {
        (_, Ok(_), _) => {
            {
                let mut st = inner.state();
                if let Some(e) = st.stempool.remove(&id) {
                    unstem_key_images(&mut st, &e.tx);
                }
            }
            inner.announce_tx(id, Some(peer));
        }
        (tip, Err(MempoolError::Invalid(e)), proven) => {
            on_invalid_tx(inner, peer, id, tip, e, proven)
        }
        (_, Err(_), _) => {}
    }
}

fn unstem_key_images(st: &mut State, tx: &Transaction) {
    for k in stem_keys(tx) {
        st.stem_key_images.remove(&k);
    }
}

async fn on_stem_tx(inner: &Arc<Inner>, peer: PeerId, bytes: Vec<u8>) {
    {
        let mut st = inner.state();
        let now = Instant::now();
        let within = match st.peers.get_mut(&peer) {
            Some(p) => p.limits.txs.take(1.0, now),
            None => return,
        };
        if !within {
            drop(st);
            inner.misbehave(peer, score::RATE, "stem rate");
            return;
        }
    }
    let Some(tx) = decode_tx(&bytes) else {
        inner.misbehave(peer, score::INVALID_TX, "stem transaction does not decode");
        return;
    };
    let id = tx.hash();
    {
        // Already stemmed, or a conflict with a stem transaction (first seen
        // wins): dropped before any verification, so valid double-spend
        // variants cost nothing (R8-7).
        let st = inner.state();
        if st.stempool.contains_key(&id)
            || stem_keys(&tx)
                .iter()
                .any(|k| st.stem_key_images.contains_key(k))
        {
            return;
        }
    }
    if !admit_tx(inner, peer, &tx, id, true).await {
        return;
    }
    let rings = input_rings(&tx);
    let tx2 = tx.clone();
    let checked = inner
        .with_chain(move |c| {
            let r = c.check_tx(&tx2);
            let proven = r.as_ref().is_err_and(|e| proven_invalid(c, &rings, e));
            (c.tip_id(), r, proven)
        })
        .await;
    inner.state().tx_verifications += 1;
    match checked {
        (_, Ok(_), _) => stem_or_fluff(inner, tx, id, Source::Peer(peer)).await,
        (tip, Err(MempoolError::Invalid(e)), proven) => {
            on_invalid_tx(inner, peer, id, tip, e, proven)
        }
        (_, Err(_), _) => {}
    }
}

/// Stem-phase handling of a validated transaction (docs/p2p.md §8).
async fn stem_or_fluff(inner: &Arc<Inner>, tx: Transaction, id: Hash, source: Source) {
    let route = {
        let mut st = inner.state();
        // Conflicts with another stem transaction: first seen wins.
        let keys = stem_keys(&tx);
        if keys.iter().any(|k| st.stem_key_images.contains_key(k)) {
            return;
        }
        for k in keys {
            st.stem_key_images.insert(k, id);
        }
        let State { dandelion, rng, .. } = &mut *st;
        let route = dandelion.route(source, rng);
        let embargo = Instant::now() + dandelion.embargo(rng);
        // A local transaction is never diffused by its origin on purpose
        // (`Dandelion::route`), so `Fluff` here means there is no stem peer
        // yet (e.g. just after startup). Broadcasting it now would show every
        // connected (inbound) spy where it comes from: hold it until a stem
        // route exists, with the embargo as the fallback.
        let hold = source == Source::Local && route == Route::Fluff;
        st.stempool.insert(
            id,
            StemEntry {
                tx: tx.clone(),
                embargo,
                awaiting_stem: hold,
            },
        );
        if hold {
            log::debug!("local tx {} held until a stem peer exists", short(&id));
            return;
        }
        route
    };
    match route {
        Route::Fluff => fluff(inner, id, None).await,
        Route::Stem(p) => {
            log::debug!("stem tx {} -> peer {p}", short(&id));
            inner.send_now(p, Message::StemTx(tx.encode()));
        }
    }
}

/// Sends local transactions held for lack of a stem peer (`stem_or_fluff`)
/// into the stem, once the epoch has one.
fn send_held_local_txs(inner: &Inner, st: &mut State) {
    if st.dandelion.stems().is_empty() {
        return;
    }
    let held: Vec<Hash> = st
        .stempool
        .iter()
        .filter(|(_, e)| e.awaiting_stem)
        .map(|(id, _)| *id)
        .collect();
    for id in held {
        let State { dandelion, rng, .. } = &mut *st;
        let Route::Stem(p) = dandelion.route(Source::Local, rng) else {
            return;
        };
        let Some(e) = st.stempool.get_mut(&id) else {
            continue;
        };
        e.awaiting_stem = false;
        let msg = Message::StemTx(e.tx.encode());
        log::debug!("held local tx {} -> stem peer {p}", short(&id));
        inner.send(st, p, msg);
    }
}

/// Moves a stem transaction into the mempool and announces it.
async fn fluff(inner: &Arc<Inner>, id: Hash, except: Option<PeerId>) {
    let entry = {
        let mut st = inner.state();
        let e = st.stempool.remove(&id);
        if let Some(e) = &e {
            unstem_key_images(&mut st, &e.tx);
        }
        e
    };
    let Some(entry) = entry else { return };
    let result = inner.with_chain(move |c| c.submit_tx(entry.tx)).await;
    match result {
        Ok(_) | Err(MempoolError::AlreadyKnown) => {
            log::debug!("fluff tx {}", short(&id));
            inner.announce_tx(id, except);
        }
        Err(e) => log::debug!("fluffing {} failed: {e:?}", short(&id)),
    }
}

// ---------------------------------------------------------------- maintenance

async fn maintenance_loop(inner: Arc<Inner>) {
    // Save soon after the first change.
    let mut last_save = Instant::now() - SAVE_INTERVAL + Duration::from_secs(5);
    let mut saved_fingerprint = (0, 0);
    let mut last_outbound = Instant::now() - Duration::from_secs(60);
    loop {
        tokio::time::sleep(inner.cfg.tick).await;
        let now = Instant::now();

        // Dandelion epoch and embargoes.
        let expired: Vec<Hash> = {
            let mut st = inner.state();
            let outbound: Vec<PeerId> = st
                .peers
                .iter()
                .filter(|(_, p)| !p.inbound && p.relay_txs)
                .map(|(id, _)| *id)
                .collect();
            let State { dandelion, rng, .. } = &mut *st;
            dandelion.maybe_new_epoch(now, &outbound, rng);
            send_held_local_txs(&inner, &mut st);
            st.stempool
                .iter()
                .filter(|(_, e)| now >= e.embargo)
                .map(|(id, _)| *id)
                .collect()
        };
        for id in expired {
            log::debug!("embargo expired for {}", short(&id));
            fluff(&inner, id, None).await;
        }

        // Announce a new tip.
        let (tip, header_height_now) = inner
            .with_chain(|c| ((c.tip_id(), *c.tip_header()), c.header_height()))
            .await;
        {
            let mut st = inner.state();
            if st.announced_tip != tip.0 {
                st.announced_tip = tip.0;
                let peers: Vec<PeerId> = st
                    .peers
                    .iter()
                    .filter(|(_, p)| p.height < tip.1.height)
                    .map(|(id, _)| *id)
                    .collect();
                for p in peers {
                    inner.send(&mut st, p, Message::Headers(vec![tip.1]));
                }
            }
        }

        // Trickled announcements, pings, timeouts.
        let mut timed_out = Vec::new();
        {
            let mut st = inner.state();
            let ids: Vec<PeerId> = st.peers.keys().copied().collect();
            for pid in ids {
                let nonce = st.rng.next_u64();
                let p = st.peers.get_mut(&pid).expect("listed");
                if !p.inv_queue.is_empty() && now >= p.next_inv {
                    let queue = std::mem::take(&mut p.inv_queue);
                    remember(&mut p.announced_to, queue.iter().copied());
                    for chunk in queue.chunks(500) {
                        let _ = p.out.try_send(Message::InvTx(chunk.to_vec()));
                    }
                }
                if let Some((_, sent)) = p.ping {
                    if now.duration_since(sent) > PONG_TIMEOUT {
                        p.kill.notify_one();
                    }
                } else if now.duration_since(p.last_ping) > PING_INTERVAL {
                    p.ping = Some((nonce, now));
                    p.last_ping = now;
                    let _ = p.out.try_send(Message::Ping(nonce));
                }
                if p.headers_requested
                    .is_some_and(|t| now.duration_since(t) > HEADERS_TIMEOUT)
                {
                    p.headers_requested = None;
                    timed_out.push((pid, "headers"));
                    // Not asked again every tick; asked again when it
                    // announces a new tip.
                    p.height = p.height.min(header_height_now);
                }
            }
            let stale_blocks: Vec<(Hash, PeerId)> = st
                .block_requests
                .iter()
                .filter(|(_, (_, t))| now.duration_since(*t) > BLOCK_TIMEOUT)
                .map(|(id, (p, _))| (*id, *p))
                .collect();
            for (id, p) in stale_blocks {
                st.block_requests.remove(&id);
                release_block_slot(&mut st, p);
                st.late_blocks.insert(id, (p, now));
                timed_out.push((p, "block"));
            }
            st.late_blocks
                .retain(|_, (_, t)| now.duration_since(*t) <= BLOCK_TIMEOUT);
            let stale_txs: Vec<(Hash, PeerId)> = st
                .tx_requests
                .iter()
                .filter(|(_, (_, t))| now.duration_since(*t) > TX_TIMEOUT)
                .map(|(id, (p, _))| (*id, *p))
                .collect();
            // Transaction relay is best effort: a slow answer is retried with the
            // next announcer but not penalized (peers answer `NotFound` when they
            // no longer have the transaction).
            for (id, p) in stale_txs {
                retry_tx(&inner, &mut st, id, p, now);
            }
        }
        // A timeout is not misbehavior: a large block on a slow link, or a
        // busy honest peer, times out too (R8-9). The request moves to another
        // peer; the late answer is still accepted without penalty.
        for (p, what) in timed_out {
            log::debug!("peer {p}: {what} request timed out");
        }

        // Keep syncing from peers that are ahead, and ask again peers whose
        // headers were dropped while the queue was full, once it has room.
        let header_height = header_height_now;
        let behind: Vec<PeerId> = {
            let st = inner.state();
            st.peers
                .iter()
                .filter(|(_, p)| {
                    (p.height > header_height || p.headers_pending)
                        && p.headers_requested.is_none()
                        && !p.headers_busy
                        && inner.header_queue_room(&st, &p.addr)
                })
                .map(|(id, _)| *id)
                .collect()
        };
        for p in behind {
            inner.request_headers(p).await;
        }
        schedule_downloads(&inner).await;

        // Outbound connections.
        if now.duration_since(last_outbound) > Duration::from_secs(2) {
            last_outbound = now;
            maintain_outbound(&inner);
        }
        // The address table is saved when its size changed; the ban list
        // whenever a ban was added (a new ban does not always change the
        // count: it may replace an expired one).
        let (fingerprint, bans_dirty) = {
            let st = inner.state();
            (st.addrman.len(), st.bans_dirty)
        };
        if (fingerprint != saved_fingerprint || bans_dirty)
            && now.duration_since(last_save) > SAVE_INTERVAL
        {
            last_save = now;
            saved_fingerprint = fingerprint;
            let mut st = inner.state();
            st.bans.prune(unix_now());
            st.bans_dirty = false;
            drop(st);
            inner.save();
        }
    }
}

fn maintain_outbound(inner: &Arc<Inner>) {
    let now = Instant::now();
    let mut to_connect = Vec::new();
    {
        let mut st = inner.state();
        let connected: HashSet<NetAddr> = st.peers.values().map(|p| p.addr.clone()).collect();
        // Manual peers: always reconnect (after a short backoff).
        for a in &inner.cfg.connect {
            if !connected.contains(a)
                && !st.connecting.contains(a)
                && st
                    .last_attempt
                    .get(a)
                    .is_none_or(|t| now.duration_since(*t) > Duration::from_secs(10))
            {
                to_connect.push(a.clone());
            }
        }
        let outbound = st.peers.values().filter(|p| !p.inbound).count() + st.connecting.len();
        let mut free = if inner.cfg.connect_only {
            0
        } else {
            inner
                .cfg
                .max_outbound
                .saturating_sub(outbound + to_connect.len())
        };
        // Seeds: when we know no address, and also when no outbound
        // connection is up (every known address may be stale or hostile),
        // each at most every SEED_RETRY.
        let registered_outbound = st.peers.values().filter(|p| !p.inbound).count();
        if free > 0 && (st.addrman.is_empty() || registered_outbound == 0) {
            for s in &inner.cfg.seeds {
                if free == 0 {
                    break;
                }
                let recent = st
                    .last_attempt
                    .get(s)
                    .is_some_and(|t| now.duration_since(*t) < SEED_RETRY);
                if !connected.contains(s) && !st.connecting.contains(s) && !recent {
                    to_connect.push(s.clone());
                    free -= 1;
                }
            }
        }
        let mut groups: HashSet<Vec<u8>> = st
            .peers
            .values()
            .filter(|p| !p.inbound)
            .map(|p| p.addr.group())
            .chain(st.connecting.iter().map(|a| a.group()))
            .collect();
        let unix = unix_now();
        let cfg = &inner.cfg;
        for _ in 0..free {
            let State {
                addrman,
                rng,
                bans,
                connecting,
                last_attempt,
                ..
            } = &mut *st;
            let pick = addrman.select(rng, |a| {
                connected.contains(a)
                    || connecting.contains(a)
                    || to_connect.contains(a)
                    || Some(a) == cfg.public_address.as_ref()
                    || a.ip().is_some_and(|ip| bans.is_banned(&ip, unix))
                    || (!cfg.allow_private && (!a.is_routable() || groups.contains(&a.group())))
                    || (a.is_onion() && cfg.proxy.is_none())
                    || last_attempt
                        .get(a)
                        .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(60))
                    || inner.local_addr.is_some_and(|l| a == &NetAddr::Ip(l))
            });
            match pick {
                Some(a) => {
                    // One outbound connection per group, also among the
                    // picks of this round (R8-4).
                    groups.insert(a.group());
                    to_connect.push(a);
                }
                None => break,
            }
        }
    }
    for a in to_connect {
        tokio::spawn(connect_outbound(inner.clone(), a));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M2: the per-peer id sets (`known_txs`, `announced_to`) stay bounded.
    #[test]
    fn remembered_ids_are_capped() {
        let mut set = HashSet::new();
        for i in 0..(3 * ANNOUNCED_CAP as u64) {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_le_bytes());
            remember(&mut set, [id]);
            assert!(set.len() <= ANNOUNCED_CAP + 1);
        }
    }

    /// R8-11: control messages queued behind block frames are written first.
    #[tokio::test]
    async fn control_messages_overtake_queued_block_frames() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let t = Duration::from_secs(5);
        let (ours, theirs) = tokio::join!(
            handshake(a, true, 7, &[3; 32], t),
            handshake(b, false, 7, &[3; 32], t)
        );
        let ((_, writer), (mut reader, _)) = (ours.unwrap(), theirs.unwrap());
        let (control_tx, control_rx) = mpsc::channel(OUTBOX);
        let (bulk_tx, bulk_rx) = mpsc::channel(BULK_OUTBOX);
        for i in 0..4u8 {
            bulk_tx.try_send(Message::Block(vec![i; 1000])).unwrap();
        }
        control_tx.try_send(Message::Pong(9)).unwrap();
        control_tx.try_send(Message::Ping(10)).unwrap();
        let task = tokio::spawn(write_loop(writer, control_rx, bulk_rx));
        let mut got = Vec::new();
        for _ in 0..6 {
            got.push(Message::decode(&reader.recv().await.unwrap()).unwrap());
        }
        assert_eq!(got[0], Message::Pong(9));
        assert_eq!(got[1], Message::Ping(10));
        assert!(got[2..]
            .iter()
            .enumerate()
            .all(|(i, m)| *m == Message::Block(vec![i as u8; 1000])));
        drop((control_tx, bulk_tx));
        task.await.unwrap();
    }

    /// R8-9: the byte window, not the count, limits maximum-size blocks
    /// (3 in flight per peer; `p2p/tests/network.rs` checks it on the wire).
    #[test]
    fn the_byte_window_is_the_binding_limit() {
        let allowed = BLOCK_WINDOW_BYTES / MAX_BLOCK_BYTES;
        assert_eq!(allowed, 3);
        assert!(allowed < BLOCKS_IN_FLIGHT);
    }

    #[test]
    fn header_queue_origins_ignore_the_port() {
        let a = NetAddr::parse("1.2.3.4:5").unwrap();
        let b = NetAddr::parse("1.2.3.4:6").unwrap();
        assert_eq!(queue_key(&a), queue_key(&b));
        assert_ne!(
            queue_key(&a),
            queue_key(&NetAddr::parse("1.2.3.5:5").unwrap())
        );
    }

    /// A header from a newer release (a version no epoch of the schedule
    /// uses) is not scored; a bad version the schedule does know is.
    #[test]
    fn unknown_upgrades_are_not_penalized() {
        assert!(!penalized(&HeaderError::UnknownUpgrade { version: 9 }));
        assert!(penalized(&HeaderError::BadVersion {
            expected: 1,
            got: 0
        }));
        assert!(!penalized(&HeaderError::Duplicate));
        assert!(penalized(&HeaderError::InsufficientWork));
    }
}
