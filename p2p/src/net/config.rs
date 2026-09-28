//! Network configuration and the public peer and statistics snapshots
//! (`NetConfig`, `PeerInfo`, `NetStats`).

use crate::addr::NetAddr;
use crate::dandelion::{DandelionParams, PeerId};
use crate::limits::PeerLimits;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

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
    /// Relayed transactions dropped unverified because the chain actor's
    /// transaction lane was full (best effort; the senders are not
    /// penalized; docs/p2p.md §10).
    pub tx_lane_drops: u64,
}
