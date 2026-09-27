//! The network manager (docs/p2p.md): connections, handshake, message handling,
//! header-first sync, block and transaction relay, Dandelion++, peer management.
//!
//! Concurrency rule: the chain lock (`ChainManager`) and the network state lock are
//! never held at the same time, and neither is held across an `.await`. CPU-heavy
//! work (PoW, block and transaction validation) runs on blocking threads.

use crate::addr::NetAddr;
use crate::addrman::{AddrMan, BanList};
use crate::dandelion::{exponential, Dandelion, DandelionParams, PeerId, Route, Source};
use crate::limits::{score, PeerLimits, BAN_SECS, BAN_THRESHOLD};
use crate::message::{Message, Version, MAX_HEADERS, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION};
use crate::socks5;
use crate::transport::{handshake, FrameReader, FrameWriter, TransportError};
use blacksilk_chain::block::Block;
use blacksilk_chain::manager::{ChainManager, SubmitError};
use blacksilk_chain::mempool::MempoolError;
use blacksilk_consensus::{BlockHeader, Hash, HeaderError};
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify};

pub type SharedChain = Arc<Mutex<ChainManager>>;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const PING_INTERVAL: Duration = Duration::from_secs(60);
const PONG_TIMEOUT: Duration = Duration::from_secs(30);
const BLOCK_TIMEOUT: Duration = Duration::from_secs(60);
const TX_TIMEOUT: Duration = Duration::from_secs(30);
const HEADERS_TIMEOUT: Duration = Duration::from_secs(60);
const BLOCKS_IN_FLIGHT: usize = 16;
const SERVE_BLOCKS_PER_REQUEST: usize = 16;
const OUTBOX: usize = 64;
const RECENT_REJECTS: usize = 10_000;
const ANNOUNCED_CAP: usize = 50_000;
/// Address table and bans are saved at most this often, and only when changed
/// (a crash loses at most this much discovery state).
const SAVE_INTERVAL: Duration = Duration::from_secs(60);

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
}

struct Peer {
    addr: NetAddr,
    inbound: bool,
    proxied: bool,
    out: mpsc::Sender<Message>,
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
    blocks_in_flight: usize,
    headers_requested: Option<Instant>,
    /// A header batch from this peer is queued for, or under, verification by
    /// the header worker. At most one per peer: the queue is bounded by the
    /// number of peers, and the peer is not asked for more headers meanwhile.
    headers_busy: bool,
    /// Headers arrived while `headers_busy`; ask again once the batch is done.
    headers_pending: bool,
}

struct StemEntry {
    tx: Transaction,
    embargo: Instant,
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
    local_nonces: HashSet<u64>,
    connecting: HashSet<NetAddr>,
    last_attempt: HashMap<NetAddr, Instant>,
    announced_tip: Hash,
    rng: ChaCha20Rng,
    misbehaving_disconnects: u64,
    slow_disconnects: u64,
}

/// A header batch waiting for the header worker, with its sender's address
/// (a sender that disconnects before its batch is verified is still banned).
struct HeaderBatch {
    peer: PeerId,
    addr: NetAddr,
    proxied: bool,
    headers: Vec<BlockHeader>,
}

struct Inner {
    chain: SharedChain,
    cfg: NetConfig,
    /// To the header worker (`header_worker`): batches are verified there, one
    /// at a time, never on a peer's read loop.
    header_queue: mpsc::UnboundedSender<HeaderBatch>,
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
        let tip = chain.lock().unwrap_or_else(|e| e.into_inner()).tip_id();
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
            local_nonces: HashSet::new(),
            connecting: HashSet::new(),
            last_attempt: HashMap::new(),
            announced_tip: tip,
            rng,
            misbehaving_disconnects: 0,
            slow_disconnects: 0,
        };
        let (header_queue, header_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            chain,
            cfg,
            header_queue,
            state: Mutex::new(state),
            next_id: AtomicU64::new(1),
            local_addr,
        });
        if let Some(l) = listener {
            tokio::spawn(accept_loop(inner.clone(), l));
        }
        tokio::spawn(maintenance_loop(inner.clone()));
        tokio::spawn(header_worker(inner.clone(), header_rx));
        Ok(Network { inner })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr
    }

    /// Submits a locally created transaction: validated, then sent into the
    /// Dandelion++ stem (docs/p2p.md §8).
    pub async fn submit_tx(&self, tx: Transaction) -> Result<Hash, String> {
        let inner = self.inner.clone();
        let tx2 = tx.clone();
        let id = tokio::task::spawn_blocking(move || inner.chain().check_tx(&tx2))
            .await
            .map_err(|e| e.to_string())?
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
        }
    }

    pub fn stempool_contains(&self, id: &Hash) -> bool {
        self.inner.state().stempool.contains_key(id)
    }

    /// Persists the address table and ban list.
    pub fn save(&self) {
        self.inner.save();
    }
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn chain(&self) -> MutexGuard<'_, ChainManager> {
        self.chain.lock().unwrap_or_else(|e| e.into_inner())
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

    fn send(&self, st: &mut State, peer: PeerId, msg: Message) {
        let Some(p) = st.peers.get(&peer) else { return };
        if p.out.try_send(msg).is_err() {
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
        let now = unix_now();
        let Some(p) = st.peers.get_mut(&peer) else {
            return;
        };
        p.score = p.score.saturating_add(points);
        log::debug!(
            "peer {} misbehaved (+{points}, {}): {reason}",
            p.addr,
            p.score
        );
        if p.score < BAN_THRESHOLD {
            return;
        }
        log::info!("disconnecting peer {} for misbehavior: {reason}", p.addr);
        p.kill.notify_one();
        let (addr, proxied) = (p.addr.clone(), p.proxied);
        st.misbehaving_disconnects += 1;
        if let Some(ip) = addr.ip() {
            let local = ip.is_loopback() && self.cfg.allow_private;
            if !proxied && !local {
                st.bans.ban(ip, now + BAN_SECS);
            }
        }
    }

    /// `misbehave` for work that finished after its sender disconnected: a
    /// violation worth a ban on its own still bans the address.
    fn misbehave_departed(&self, batch: &HeaderBatch, points: u32, reason: &str) {
        if self.state().peers.contains_key(&batch.peer) {
            return self.misbehave(batch.peer, points, reason);
        }
        if points < BAN_THRESHOLD {
            return;
        }
        log::info!(
            "banning departed peer {} for misbehavior: {reason}",
            batch.addr
        );
        let mut st = self.state();
        st.misbehaving_disconnects += 1;
        if let Some(ip) = batch.addr.ip() {
            let local = ip.is_loopback() && self.cfg.allow_private;
            if !batch.proxied && !local {
                st.bans.ban(ip, unix_now() + BAN_SECS);
            }
        }
    }

    fn locator(&self) -> Vec<Hash> {
        self.chain().locator()
    }

    fn request_headers(&self, peer: PeerId) {
        let locator = self.locator();
        let mut st = self.state();
        if let Some(p) = st.peers.get_mut(&peer) {
            p.headers_requested = Some(Instant::now());
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
        {
            let st = inner.state();
            let inbound = st.peers.values().filter(|p| p.inbound).count();
            let same_ip = st
                .peers
                .values()
                .filter(|p| p.addr.ip() == Some(remote.ip()))
                .count();
            if st.bans.is_banned(&remote.ip(), unix_now())
                || inbound >= inner.cfg.max_inbound
                || (!inner.cfg.allow_private && same_ip >= inner.cfg.max_per_ip)
            {
                continue; // drop the socket
            }
        }
        let _ = stream.set_nodelay(true);
        tokio::spawn(run_connection(inner.clone(), stream, addr, true, false));
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
            run_connection(inner.clone(), stream, addr.clone(), false, proxied).await;
        }
        _ => {
            log::debug!("connect {addr} failed");
            inner.state().addrman.mark_failed(&addr);
        }
    }
    inner.state().connecting.remove(&addr);
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
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let nid = inner.cfg.network_id;
    let (mut reader, mut writer) = match handshake(stream, !inbound, nid, HANDSHAKE_TIMEOUT).await {
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
    let (height, tip) = {
        let c = inner.chain();
        (c.header_height(), c.best_header_id())
    };
    let ours = Version {
        protocol: PROTOCOL_VERSION,
        network: nid,
        nonce,
        height,
        tip,
        listen: inner.cfg.public_address.clone(),
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
        match recv_msg(&mut reader, HANDSHAKE_TIMEOUT).await? {
            Message::Verack => Ok(theirs),
            other => Err(format!("expected verack, got {}", other.kind())),
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
    let kill = Arc::new(Notify::new());
    let id = inner.next_id.fetch_add(1, Ordering::Relaxed);
    {
        let mut st = inner.state();
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
                out: tx_out,
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
                headers_requested: None,
                headers_busy: false,
                headers_pending: false,
            },
        );
    }
    log::info!(
        "connected {} peer {addr} (height {})",
        if inbound { "inbound" } else { "outbound" },
        theirs.height
    );
    let writer_task = tokio::spawn(write_loop(writer, rx_out));
    if !inbound {
        inner.send_now(id, Message::GetAddr);
    }
    if theirs.height > height {
        inner.request_headers(id);
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
    st.tx_requests.retain(|_, (p, _)| *p != id);
    for q in st.tx_announcers.values_mut() {
        q.retain(|p| *p != id);
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(
    mut writer: FrameWriter<W>,
    mut rx: mpsc::Receiver<Message>,
) {
    while let Some(msg) = rx.recv().await {
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
        Message::Headers(_) => {
            return inner
                .state()
                .peers
                .get(&peer)
                .is_some_and(|p| p.headers_requested.is_some());
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
    inner
        .state()
        .block_requests
        .get(&id)
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
                .chain()
                .headers_after(&locator, &stop, MAX_HEADERS as usize);
            inner.send_now(peer, Message::Headers(headers));
        }
        Message::Headers(headers) => on_headers(inner, peer, headers),
        Message::GetBlocks(ids) => on_get_blocks(inner, peer, ids),
        Message::Block(bytes) => on_block(inner, peer, bytes).await,
        Message::NotFound(ids) => {
            let mut st = inner.state();
            let now = Instant::now();
            for id in ids {
                if st.block_requests.get(&id).is_some_and(|(p, _)| *p == peer) {
                    st.block_requests.remove(&id);
                    if let Some(p) = st.peers.get_mut(&peer) {
                        p.blocks_in_flight = p.blocks_in_flight.saturating_sub(1);
                    }
                }
                if st.tx_requests.get(&id).is_some_and(|(p, _)| *p == peer) {
                    retry_tx(inner, &mut st, id, peer, now);
                }
            }
        }
        Message::InvTx(ids) => on_inv_tx(inner, peer, ids).await,
        Message::GetTx(ids) => on_get_tx(inner, peer, ids),
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

/// Receives a `Headers` message on the peer's read loop. Only cheap checks run
/// here; the batch is verified by the header worker, so the read loop keeps
/// answering pings however long the proof of work takes (docs/p2p.md §6).
fn on_headers(inner: &Arc<Inner>, peer: PeerId, headers: Vec<BlockHeader>) {
    let nid = inner.cfg.network_id;
    let penalty = {
        let mut st = inner.state();
        let Some(p) = st.peers.get_mut(&peer) else {
            return;
        };
        let solicited = p.headers_requested.take().is_some();
        if headers.is_empty() {
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
        } else if p.headers_busy {
            // Still verifying this peer's previous batch; ask again afterwards.
            p.headers_pending = true;
            None
        } else {
            p.headers_busy = true;
            let batch = HeaderBatch {
                peer,
                addr: p.addr.clone(),
                proxied: p.proxied,
                headers,
            };
            if inner.header_queue.send(batch).is_err() {
                p.headers_busy = false;
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
    /// Every header is stored (new or already known); `last` is the height of
    /// the last one.
    Accepted { last: u64 },
    /// The first header does not connect to anything we know.
    Unconnected,
    /// A header failed; the ones before it are stored.
    Failed(HeaderError),
}

/// Verifies header batches one at a time (docs/p2p.md §6):
/// 1. every rule except proof of work, for the whole batch, before any RandomX
///    hash (`ChainManager::precheck_headers`);
/// 2. proof of work in chunks of `pow_threads` headers, each chunk accepted
///    before the next is hashed, so a batch that fails costs at most one
///    chunk of hashes beyond its last valid header.
///
/// One worker for all peers: batches from several peers covering the same
/// headers are hashed once (the second finds them stored).
async fn header_worker(inner: Arc<Inner>, mut rx: mpsc::UnboundedReceiver<HeaderBatch>) {
    while let Some(mut batch) = rx.recv().await {
        let peer = batch.peer;
        let headers = std::mem::take(&mut batch.headers);
        let full = headers.len() as u64 == MAX_HEADERS;
        let count = headers.len();
        let last_height = headers.last().map_or(0, |h| h.height);
        let inner2 = inner.clone();
        let outcome = tokio::task::spawn_blocking(move || verify_headers(&inner2, &headers)).await;
        let pending = {
            let mut st = inner.state();
            match st.peers.get_mut(&peer) {
                Some(p) => {
                    p.headers_busy = false;
                    std::mem::take(&mut p.headers_pending)
                }
                None => false,
            }
        };
        match outcome {
            Ok(HeaderOutcome::Accepted { last }) => {
                if let Some(p) = inner.state().peers.get_mut(&peer) {
                    p.height = p.height.max(last);
                }
                if full || pending {
                    inner.request_headers(peer);
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
                inner.request_headers(peer);
            }
            Ok(HeaderOutcome::Failed(e)) => {
                on_header_error(&inner, &batch, e, last_height, pending)
            }
            Err(e) => log::error!("header task failed: {e}"),
        }
        schedule_downloads(&inner);
    }
}

/// Pre-check, then chunked proof of work and acceptance. Runs on a blocking
/// thread; the chain lock is held only for the cheap steps, never while
/// hashing.
fn verify_headers(inner: &Inner, headers: &[BlockHeader]) -> HeaderOutcome {
    let now = unix_now();
    let checked = {
        let c = inner.chain();
        if c.header(&headers[0].prev_id).is_none() {
            return HeaderOutcome::Unconnected;
        }
        c.precheck_headers(headers, now)
    };
    let (good, precheck_error) = match checked {
        Ok(()) => (headers, None),
        Err((i, e)) => (&headers[..i], Some(e)),
    };
    let chunk = inner.cfg.pow_threads.max(1);
    for part in good.chunks(chunk) {
        let jobs = inner.chain().pow_jobs(part);
        let Some((pow, jobs)) = jobs else {
            return HeaderOutcome::Unconnected;
        };
        pow.compute_parallel(&jobs, chunk);
        if let Err((_, e)) = inner.chain().accept_headers(part, now) {
            return HeaderOutcome::Failed(e);
        }
    }
    match precheck_error {
        Some(e) => HeaderOutcome::Failed(e),
        None => HeaderOutcome::Accepted {
            last: headers.last().map_or(0, |h| h.height),
        },
    }
}

/// Penalties for a failed header batch. Only failures a peer can check itself
/// from the headers are penalized:
/// - `InvalidParent` means the header descends from a block whose *body* we
///   found invalid. A peer relaying headers cannot know that without the body
///   (it may not have downloaded it yet, or its sender withholds it), so it is
///   not penalized; we stop asking it for headers until it announces again.
/// - `Duplicate` and `TimestampTooFarInFuture` are not permanent.
/// - Every other failure is a header that breaks the rules: the peer relayed
///   it without checking, and is penalized.
fn on_header_error(
    inner: &Arc<Inner>,
    batch: &HeaderBatch,
    e: HeaderError,
    last_height: u64,
    pending: bool,
) {
    let peer = batch.peer;
    match e {
        HeaderError::Duplicate | HeaderError::TimestampTooFarInFuture { .. } => {}
        HeaderError::UnknownParent => inner.request_headers(peer),
        HeaderError::InvalidParent => {
            log::info!(
                "peer {peer} relays headers (up to height {last_height}) descending from a block with an invalid body"
            );
            let ours = inner.chain().header_height();
            if let Some(p) = inner.state().peers.get_mut(&peer) {
                p.height = p.height.min(ours);
            }
            if pending {
                inner.request_headers(peer);
            }
        }
        e => inner.misbehave_departed(
            batch,
            score::INVALID_HEADER,
            &format!("invalid header: {e}"),
        ),
    }
}

fn on_get_blocks(inner: &Arc<Inner>, peer: PeerId, ids: Vec<Hash>) {
    let (found, missing): (Vec<Block>, Vec<Hash>) = {
        let c = inner.chain();
        let mut found = Vec::new();
        let mut missing = Vec::new();
        for id in ids {
            match c.block(&id) {
                Some(b) if found.len() < SERVE_BLOCKS_PER_REQUEST => found.push(b),
                _ => missing.push(id),
            }
        }
        (found, missing)
    };
    let mut st = inner.state();
    for b in found {
        inner.send(&mut st, peer, Message::Block(b.encode()));
    }
    if !missing.is_empty() {
        inner.send(&mut st, peer, Message::NotFound(missing));
    }
}

async fn on_block(inner: &Arc<Inner>, peer: PeerId, bytes: Vec<u8>) {
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
    let requested = {
        let mut st = inner.state();
        let req = st.block_requests.get(&id).is_some_and(|(p, _)| *p == peer);
        if req {
            st.block_requests.remove(&id);
            if let Some(p) = st.peers.get_mut(&peer) {
                p.blocks_in_flight = p.blocks_in_flight.saturating_sub(1);
            }
        }
        req
    };
    if !requested {
        inner.misbehave(peer, score::UNSOLICITED, "unrequested block");
    }
    let inner2 = inner.clone();
    let result =
        tokio::task::spawn_blocking(move || inner2.chain().submit_block(block, unix_now())).await;
    match result {
        Ok(Ok(_)) | Ok(Err(SubmitError::Duplicate)) => {}
        Ok(Err(SubmitError::BodyMismatch)) => {
            inner.misbehave(peer, score::INVALID_BLOCK, "body does not match header")
        }
        Ok(Err(SubmitError::Body(e))) => {
            inner.misbehave(peer, score::INVALID_BLOCK, &format!("invalid block: {e:?}"))
        }
        Ok(Err(SubmitError::Header(e))) => match e {
            // `InvalidParent`: the parent's body was found invalid, possibly
            // after we requested this block (a race), so it is not the
            // sender's fault; an unrequested block was already charged above.
            HeaderError::Duplicate
            | HeaderError::TimestampTooFarInFuture { .. }
            | HeaderError::InvalidParent => {}
            HeaderError::UnknownParent => inner.request_headers(peer),
            e => inner.misbehave(
                peer,
                score::INVALID_HEADER,
                &format!("invalid block header: {e}"),
            ),
        },
        Ok(Err(SubmitError::Store(e))) => log::error!("block store: {e}"),
        Err(e) => log::error!("block task failed: {e}"),
    }
    schedule_downloads(inner);
}

/// Requests missing best-chain bodies from peers that have them (docs/p2p.md §6).
fn schedule_downloads(inner: &Arc<Inner>) {
    let missing = inner.chain().missing_bodies(256);
    if missing.is_empty() {
        return;
    }
    let mut st = inner.state();
    let now = Instant::now();
    let mut batches: HashMap<PeerId, Vec<Hash>> = HashMap::new();
    for (height, id) in missing {
        if st.block_requests.contains_key(&id) {
            continue;
        }
        let candidates: Vec<PeerId> = st
            .peers
            .iter()
            .filter(|(_, p)| p.height >= height && p.blocks_in_flight < BLOCKS_IN_FLIGHT)
            .map(|(id, _)| *id)
            .collect();
        if candidates.is_empty() {
            break;
        }
        let pick = candidates[(st.rng.next_u64() % candidates.len() as u64) as usize];
        st.peers.get_mut(&pick).expect("candidate").blocks_in_flight += 1;
        st.block_requests.insert(id, (pick, now));
        batches.entry(pick).or_default().push(id);
    }
    for (peer, ids) in batches {
        inner.send(&mut st, peer, Message::GetBlocks(ids));
    }
}

async fn on_inv_tx(inner: &Arc<Inner>, peer: PeerId, ids: Vec<Hash>) {
    let known: Vec<bool> = {
        let c = inner.chain();
        ids.iter().map(|id| c.mempool().contains(id)).collect()
    };
    let mut to_fluff = Vec::new();
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
        for id in &ids {
            p.known_txs.insert(*id);
        }
        for (id, in_mempool) in ids.into_iter().zip(known) {
            if in_mempool || st.recent_rejects_set.contains(&id) {
                continue;
            }
            if st.stempool.contains_key(&id) {
                // Seen in fluff: stop the embargo and diffuse it ourselves.
                to_fluff.push(id);
                continue;
            }
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
    for id in to_fluff {
        fluff(inner, id, None).await;
    }
}

fn on_get_tx(inner: &Arc<Inner>, peer: PeerId, ids: Vec<Hash>) {
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
    let mut txs = Vec::new();
    let mut missing = Vec::new();
    {
        let c = inner.chain();
        for (id, ok) in announced {
            match c.mempool().get(&id).filter(|_| ok) {
                Some(t) => txs.push(t.encode()),
                None => missing.push(id),
            }
        }
    }
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

/// Outcome of charging a PX or deploy transaction to the relay limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PxRate {
    Within,
    /// This peer sent more than its own share.
    PeerExceeded,
    /// All peers together are over the node-wide limit. This says nothing
    /// about this peer, which may be honest (an attacker can drain the
    /// global bucket), so it is never penalized for it.
    GlobalExceeded,
}

/// Charges a received PX or deploy transaction (expensive to verify) to the
/// peer's PX bucket, then to the node-wide one.
fn px_rate(inner: &Arc<Inner>, peer: PeerId, tx: &Transaction) -> PxRate {
    if !matches!(tx, Transaction::Px(_) | Transaction::PxDeploy(_)) {
        return PxRate::Within;
    }
    let mut st = inner.state();
    let now = Instant::now();
    let per_peer = match st.peers.get_mut(&peer) {
        Some(p) => p.limits.px.take(1.0, now),
        None => false,
    };
    if !per_peer {
        PxRate::PeerExceeded
    } else if !st.px_global.take(1.0, now) {
        PxRate::GlobalExceeded
    } else {
        PxRate::Within
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
    // A requested transaction is never penalized for its rate: we asked for
    // it. Over the limit, it is dropped unverified.
    if px_rate(inner, peer, &tx) != PxRate::Within {
        log::debug!("PX transaction {} dropped: relay limit", short(&id));
        return;
    }
    let inner2 = inner.clone();
    let result = tokio::task::spawn_blocking(move || inner2.chain().submit_tx(tx)).await;
    match result {
        Ok(Ok(_)) => {
            {
                let mut st = inner.state();
                if let Some(e) = st.stempool.remove(&id) {
                    unstem_key_images(&mut st, &e.tx);
                }
            }
            inner.announce_tx(id, Some(peer));
        }
        Ok(Err(MempoolError::Invalid(e))) if e.is_stateless() => {
            Inner::reject_cache(&mut inner.state(), id);
            inner.misbehave(
                peer,
                score::INVALID_TX,
                &format!("invalid transaction: {e:?}"),
            );
        }
        // Contextual failures (spent key image, ring members on another branch)
        // can be honest races: drop the transaction without penalty or caching.
        Ok(Err(MempoolError::Invalid(e))) => {
            log::debug!("transaction {} not valid here: {e:?}", short(&id));
        }
        Ok(Err(_)) => {}
        Err(e) => log::error!("tx task failed: {e}"),
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
    match px_rate(inner, peer, &tx) {
        PxRate::Within => {}
        PxRate::PeerExceeded => {
            inner.misbehave(peer, score::RATE, "PX stem rate");
            return;
        }
        PxRate::GlobalExceeded => return,
    }
    let id = tx.hash();
    if inner.state().stempool.contains_key(&id) {
        return;
    }
    let inner2 = inner.clone();
    let tx2 = tx.clone();
    let checked = tokio::task::spawn_blocking(move || inner2.chain().check_tx(&tx2)).await;
    match checked {
        Ok(Ok(_)) => stem_or_fluff(inner, tx, id, Source::Peer(peer)).await,
        Ok(Err(MempoolError::Invalid(e))) if e.is_stateless() => inner.misbehave(
            peer,
            score::INVALID_TX,
            &format!("invalid stem transaction: {e:?}"),
        ),
        Ok(Err(MempoolError::Invalid(e))) => {
            log::debug!("stem transaction {} not valid here: {e:?}", short(&id));
        }
        Ok(Err(_)) => {}
        Err(e) => log::error!("stem task failed: {e}"),
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
        st.stempool.insert(
            id,
            StemEntry {
                tx: tx.clone(),
                embargo,
            },
        );
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
    let inner2 = inner.clone();
    let result = tokio::task::spawn_blocking(move || inner2.chain().submit_tx(entry.tx)).await;
    match result {
        Ok(Ok(_)) | Ok(Err(MempoolError::AlreadyKnown)) => {
            log::debug!("fluff tx {}", short(&id));
            inner.announce_tx(id, except);
        }
        Ok(Err(e)) => log::debug!("fluffing {} failed: {e:?}", short(&id)),
        Err(e) => log::error!("fluff task failed: {e}"),
    }
}

// ---------------------------------------------------------------- maintenance

async fn maintenance_loop(inner: Arc<Inner>) {
    // Save soon after the first change.
    let mut last_save = Instant::now() - SAVE_INTERVAL + Duration::from_secs(5);
    let mut saved_fingerprint = ((0, 0), 0);
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
        let tip = {
            let c = inner.chain();
            let id = c.tip_id();
            (id, *c.tip_header())
        };
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
                    if p.announced_to.len() > ANNOUNCED_CAP {
                        p.announced_to.clear();
                    }
                    p.announced_to.extend(queue.iter().copied());
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
                if let Some(peer) = st.peers.get_mut(&p) {
                    peer.blocks_in_flight = peer.blocks_in_flight.saturating_sub(1);
                }
                timed_out.push((p, "block"));
            }
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
        for (p, what) in timed_out {
            inner.misbehave(p, score::TIMEOUT, &format!("{what} request timed out"));
        }

        // Keep syncing from peers that are ahead.
        let header_height = inner.chain().header_height();
        let behind: Vec<PeerId> = inner
            .state()
            .peers
            .iter()
            .filter(|(_, p)| {
                p.height > header_height && p.headers_requested.is_none() && !p.headers_busy
            })
            .map(|(id, _)| *id)
            .collect();
        for p in behind {
            inner.request_headers(p);
        }
        schedule_downloads(&inner);

        // Outbound connections.
        if now.duration_since(last_outbound) > Duration::from_secs(2) {
            last_outbound = now;
            maintain_outbound(&inner);
        }
        let fingerprint = {
            let st = inner.state();
            (st.addrman.len(), st.bans.len())
        };
        if fingerprint != saved_fingerprint && now.duration_since(last_save) > SAVE_INTERVAL {
            last_save = now;
            saved_fingerprint = fingerprint;
            let mut st = inner.state();
            st.bans.prune(unix_now());
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
        if free > 0 && st.addrman.is_empty() {
            for s in &inner.cfg.seeds {
                if free == 0 {
                    break;
                }
                if !connected.contains(s) && !st.connecting.contains(s) {
                    to_connect.push(s.clone());
                    free -= 1;
                }
            }
        }
        let groups: HashSet<Vec<u8>> = st
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
                Some(a) => to_connect.push(a),
                None => break,
            }
        }
    }
    for a in to_connect {
        tokio::spawn(connect_outbound(inner.clone(), a));
    }
}
