//! Shared helpers of the liveness tests (`liveness.rs`): a node over a
//! [`stall::SlowStore`], raw peers, pong timing and chain-lock holds.
#![allow(dead_code)]

#[path = "../../../chain/tests/support/stall.rs"]
pub mod stall;

use blacksilk_chain::actor::{self, ActorConfig, ChainHandle};
use blacksilk_chain::manager::ChainManager;
use blacksilk_consensus::{ChainParams, Hash, PowFunction};
use blacksilk_p2p::dandelion::DandelionParams;
use blacksilk_p2p::message::{Message, Version, PROTOCOL_VERSION};
use blacksilk_p2p::transport::{handshake, FrameReader, FrameWriter};
use blacksilk_p2p::{NetAddr, NetConfig, Network, SharedChain};
use blacksilk_tx::params::TxRules;
use stall::{next_block, Holder, SlowStore, StallControl};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;

pub struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

pub fn params() -> ChainParams {
    ChainParams::regtest()
}

pub fn fast_config(connect: &[SocketAddr]) -> NetConfig {
    let mut cfg = NetConfig::new(params().network_id);
    cfg.listen = Some("127.0.0.1:0".parse().unwrap());
    cfg.allow_private = true;
    cfg.connect = connect.iter().map(|a| NetAddr::Ip(*a)).collect();
    cfg.max_outbound = 4;
    cfg.trickle_outbound = Duration::from_millis(50);
    cfg.trickle_inbound = Duration::from_millis(50);
    cfg.tick = Duration::from_millis(50);
    cfg.pow_threads = 2;
    cfg.dandelion = DandelionParams {
        epoch_min: Duration::from_secs(600),
        epoch_max: Duration::from_secs(600),
        fluff_probability: 0.0,
        stem_peers: 2,
        embargo_base: Duration::from_millis(1500),
        embargo_mean: Duration::from_millis(500),
    };
    cfg
}

/// A running node whose block store can stall on demand.
pub struct SlowNode {
    /// The manager's lock, kept by the test for direct reads (the chain
    /// actor locks it for each command).
    pub chain: SharedChain,
    /// The node's chain actor.
    pub actor: ChainHandle,
    pub net: Network,
    pub addr: SocketAddr,
    pub ctl: Arc<StallControl>,
}

pub async fn slow_node(seed: u64, cfg: NetConfig) -> SlowNode {
    slow_node_with(seed, cfg, ActorConfig::default()).await
}

/// [`slow_node`] with the chain actor configured by `actor_cfg`.
pub async fn slow_node_with(seed: u64, cfg: NetConfig, actor_cfg: ActorConfig) -> SlowNode {
    let p = params();
    let (store, ctl) = SlowStore::new();
    let m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::new(store),
        [seed as u8; 32],
    )
    .unwrap();
    let chain: SharedChain = Arc::new(Mutex::new(m));
    let (handle, _thread) = actor::spawn_shared(chain.clone(), actor_cfg);
    let net = Network::start_with(cfg, handle.clone()).await.unwrap();
    let addr = net.local_addr().unwrap();
    SlowNode {
        chain,
        actor: handle,
        net,
        addr,
        ctl,
    }
}

impl SlowNode {
    /// Connects `n` coinbase-only blocks (before any hold; takes the chain
    /// lock on a blocking thread).
    pub async fn mine(&self, n: u64) {
        let chain = self.chain.clone();
        tokio::task::spawn_blocking(move || {
            let mut c = chain.lock().unwrap();
            for i in 0..n {
                let b = next_block(&c, 0x6e00 + i, 0);
                let now = b.header.timestamp;
                c.submit_block(b, now).unwrap();
            }
        })
        .await
        .unwrap();
    }

    /// Starts a hold of at most `max`: a stalled block append in a block
    /// submitted to the chain actor, which is busy with it (and holds the
    /// manager's lock) until the stall ends; returns once it has started.
    pub async fn hold(&self, max: Duration) -> Holder {
        let (chain, ctl) = (self.actor.clone(), self.ctl.clone());
        tokio::task::spawn_blocking(move || Holder::start_actor(chain, ctl, max))
            .await
            .unwrap()
    }

    /// `(height, header height)`, read on a blocking thread.
    pub async fn heights(&self) -> (u64, u64) {
        let c = self.chain.clone();
        tokio::task::spawn_blocking(move || {
            let c = c.lock().unwrap();
            (c.height(), c.header_height())
        })
        .await
        .unwrap()
    }
}

pub type RawReader = FrameReader<ReadHalf<TcpStream>>;
pub type RawWriter = FrameWriter<WriteHalf<TcpStream>>;

/// A hand-driven peer's handshake with the node at `addr`, claiming a chain of
/// `height` blocks. Returns the node's `Version` and the open connection, or
/// `None` if it did not complete within `secs`.
pub async fn raw_handshake(
    addr: SocketAddr,
    height: u64,
    secs: f64,
) -> Option<(Version, RawReader, RawWriter)> {
    let nid = params().network_id;
    tokio::time::timeout(Duration::from_secs_f64(secs), async move {
        let s = TcpStream::connect(addr).await.ok()?;
        let (mut r, mut w) = handshake(
            s,
            true,
            nid,
            &params().genesis_id(),
            Duration::from_secs(30),
        )
        .await
        .ok()?;
        let v = Version {
            protocol: PROTOCOL_VERSION,
            network: nid,
            nonce: 0xdead_beef,
            height,
            tip: [0; 32],
            listen: None,
            relay_txs: true,
        };
        w.send(&Message::Version(v).encode()).await.ok()?;
        let Message::Version(theirs) = Message::decode(&r.recv().await.ok()?).ok()? else {
            return None;
        };
        w.send(&Message::Verack.encode()).await.ok()?;
        let m = Message::decode(&r.recv().await.ok()?).ok()?;
        matches!(m, Message::Verack).then_some((theirs, r, w))
    })
    .await
    .ok()
    .flatten()
}

/// A raw peer at height 0 that must complete its handshake within 5 s.
pub async fn raw_peer(addr: SocketAddr) -> (RawReader, RawWriter) {
    let (_, r, w) = raw_handshake(addr, 0, 5.0).await.expect("handshake");
    (r, w)
}

/// Reads messages until one matches `want`, keeping the others in `other`;
/// `None` if the connection closes or `secs` pass first.
pub async fn recv_until(
    r: &mut RawReader,
    secs: f64,
    other: &mut Vec<Message>,
    want: impl Fn(&Message) -> bool,
) -> Option<Message> {
    tokio::time::timeout(Duration::from_secs_f64(secs), async {
        loop {
            let frame = r.recv().await.ok()?;
            let m = Message::decode(&frame).ok()?;
            if want(&m) {
                return Some(m);
            }
            other.push(m);
        }
    })
    .await
    .ok()
    .flatten()
}

/// Sends a ping and returns how long its pong took (`None`: none within
/// `secs`); other messages received meanwhile go to `other`.
pub async fn pong_latency(
    r: &mut RawReader,
    w: &mut RawWriter,
    nonce: u64,
    secs: f64,
    other: &mut Vec<Message>,
) -> Option<f64> {
    let start = Instant::now();
    w.send(&Message::Ping(nonce).encode()).await.ok()?;
    recv_until(
        r,
        secs,
        other,
        |m| matches!(m, Message::Pong(n) if *n == nonce),
    )
    .await?;
    Some(start.elapsed().as_secs_f64())
}

/// A `GetHeaders` from genesis (the reply lists every header after it).
pub fn get_headers_from_genesis() -> Vec<u8> {
    Message::GetHeaders {
        locator: vec![params().genesis_id()],
        stop: [0; 32],
    }
    .encode()
}
